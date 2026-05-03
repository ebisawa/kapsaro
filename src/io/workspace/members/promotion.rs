// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::paths::{
    ensure_members_dir, get_incoming_member_file_path, member_file_path, members_dir, MemberStatus,
};
use super::store::{
    check_workspace_member_kid_uniqueness, load_json_files_in_dir,
    load_verified_member_file_from_path, MemberKidCandidate,
};
use crate::support::fs::{
    atomic, ensure_text_file_matches_snapshot_with_limit, load_text_with_limit, lock,
};
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMemberPromotionSnapshot {
    pub member_handle: String,
    pub kid: String,
    pub source_path: PathBuf,
    pub source_content: String,
}

struct PromotionPlan {
    source: PathBuf,
    destination: PathBuf,
    member_handle: String,
}

fn build_promotion_plan(
    workspace_path: &Path,
    member_handles: Option<&[String]>,
) -> Result<Vec<PromotionPlan>> {
    let plans = match member_handles {
        Some(ids) => build_plans_from_ids(workspace_path, ids)?,
        None => build_plans_from_incoming_dir(workspace_path)?,
    };
    ensure_promotion_kids_are_unique(workspace_path, &plans)?;
    Ok(plans)
}

/// Build plans from a caller-supplied list of incoming member handles.
fn build_plans_from_ids(
    workspace_path: &Path,
    member_handles: &[String],
) -> Result<Vec<PromotionPlan>> {
    member_handles
        .iter()
        .map(|member_handle| build_plan_for_id(workspace_path, member_handle))
        .collect()
}

fn build_plan_for_id(workspace_path: &Path, member_handle: &str) -> Result<PromotionPlan> {
    let source = get_incoming_member_file_path(workspace_path, member_handle);
    if !source.exists() {
        return Err(Error::NotFound {
            message: format!("Member '{}' not found in incoming/", member_handle),
        });
    }

    let destination = member_file_path(workspace_path, MemberStatus::Active, member_handle);

    Ok(PromotionPlan {
        source,
        destination,
        member_handle: member_handle.to_string(),
    })
}

/// Build plans by scanning every JSON file in `members/incoming/`.
fn build_plans_from_incoming_dir(workspace_path: &Path) -> Result<Vec<PromotionPlan>> {
    let incoming_dir = members_dir(workspace_path, MemberStatus::Incoming);
    let active_dir = members_dir(workspace_path, MemberStatus::Active);
    load_json_files_in_dir(&incoming_dir)?
        .into_iter()
        .map(|source| build_plan_from_incoming_file(&active_dir, source))
        .collect()
}

fn build_plan_from_incoming_file(active_dir: &Path, source: PathBuf) -> Result<PromotionPlan> {
    let member_handle = source
        .file_stem()
        .and_then(|s| s.to_str())
        .map(String::from)
        .ok_or_else(|| {
            Error::build_io_error(format!(
                "Invalid file name: {}",
                format_path_relative_to_cwd(&source)
            ))
        })?;

    let destination = active_dir.join(format!("{}.json", member_handle));

    Ok(PromotionPlan {
        source,
        destination,
        member_handle,
    })
}

fn execute_promotion_plan(workspace_path: &Path, plans: &[PromotionPlan]) -> Result<Vec<String>> {
    if plans.is_empty() {
        return Ok(Vec::new());
    }

    ensure_members_dir(workspace_path, MemberStatus::Active)?;

    for plan in plans {
        // Re-verify the source at promotion time and route through the
        // hardened reader so a symlinked incoming file is rejected instead
        // of followed to an arbitrary location.
        load_verified_member_file_from_path(&plan.source)?;
        let source_content = load_text_with_limit(
            &plan.source,
            MAX_JSON_DOCUMENT_READ_SIZE,
            "incoming member file",
        )?;
        atomic::save_text(&plan.destination, &source_content)?;
        fs::remove_file(&plan.source).map_err(|e| {
            Error::build_io_error_with_source(
                format!(
                    "Failed to clean incoming member '{}': {}",
                    plan.member_handle, e
                ),
                e,
            )
        })?;
    }

    Ok(plans
        .iter()
        .map(|plan| plan.member_handle.clone())
        .collect())
}

pub fn promote_incoming_members(workspace_path: &Path) -> Result<Vec<String>> {
    let plans = build_promotion_plan(workspace_path, None)?;
    execute_promotion_plan(workspace_path, &plans)
}

pub fn promote_specified_incoming_members(
    workspace_path: &Path,
    member_handles: &[String],
) -> Result<Vec<String>> {
    let plans = build_promotion_plan(workspace_path, Some(member_handles))?;
    execute_promotion_plan(workspace_path, &plans)
}

pub fn promote_snapshotted_incoming_members(
    workspace_path: &Path,
    snapshots: &[IncomingMemberPromotionSnapshot],
) -> Result<Vec<String>> {
    if snapshots.is_empty() {
        return Ok(Vec::new());
    }

    ensure_snapshotted_promotion_kids_are_unique(workspace_path, snapshots)?;
    ensure_members_dir(workspace_path, MemberStatus::Active)?;

    for snapshot in snapshots {
        promote_snapshotted_member(workspace_path, snapshot)?;
    }

    Ok(snapshots
        .iter()
        .map(|snapshot| snapshot.member_handle.clone())
        .collect())
}

fn promote_snapshotted_member(
    workspace_path: &Path,
    snapshot: &IncomingMemberPromotionSnapshot,
) -> Result<()> {
    let destination = member_file_path(
        workspace_path,
        MemberStatus::Active,
        &snapshot.member_handle,
    );
    with_promotion_file_locks(&snapshot.source_path, &destination, || {
        let subject_display = format!("Incoming member '{}'", snapshot.member_handle);
        ensure_text_file_matches_snapshot_with_limit(
            &snapshot.source_path,
            Some(&snapshot.source_content),
            &subject_display,
            MAX_JSON_DOCUMENT_READ_SIZE,
        )?;
        atomic::save_text(&destination, &snapshot.source_content)?;
        fs::remove_file(&snapshot.source_path).map_err(|e| {
            Error::build_io_error_with_source(
                format!(
                    "Failed to clean incoming member '{}': {}",
                    snapshot.member_handle, e
                ),
                e,
            )
        })
    })
}

fn with_promotion_file_locks<T, F>(source_path: &Path, destination_path: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let source_key = source_path.as_os_str().to_string_lossy();
    let destination_key = destination_path.as_os_str().to_string_lossy();
    let mut action = Some(f);

    if source_key <= destination_key {
        lock::with_file_lock(source_path, || {
            lock::with_file_lock(destination_path, || action.take().unwrap()())
        })
    } else {
        lock::with_file_lock(destination_path, || {
            lock::with_file_lock(source_path, || action.take().unwrap()())
        })
    }
}

fn ensure_promotion_kids_are_unique(workspace_path: &Path, plans: &[PromotionPlan]) -> Result<()> {
    let candidates = plans
        .iter()
        .map(|plan| {
            let public_key = load_verified_member_file_from_path(&plan.source)?;
            Ok(MemberKidCandidate {
                member_handle: plan.member_handle.clone(),
                kid: public_key.protected.kid,
                status: MemberStatus::Active,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let ignored_existing = plans
        .iter()
        .flat_map(|plan| {
            [
                (MemberStatus::Active, plan.member_handle.clone()),
                (MemberStatus::Incoming, plan.member_handle.clone()),
            ]
        })
        .collect::<Vec<_>>();
    check_workspace_member_kid_uniqueness(
        workspace_path,
        &candidates,
        &ignored_existing,
        &[MemberStatus::Active, MemberStatus::Incoming],
    )
}

fn ensure_snapshotted_promotion_kids_are_unique(
    workspace_path: &Path,
    snapshots: &[IncomingMemberPromotionSnapshot],
) -> Result<()> {
    let candidates = snapshots
        .iter()
        .map(|snapshot| MemberKidCandidate {
            member_handle: snapshot.member_handle.clone(),
            kid: snapshot.kid.clone(),
            status: MemberStatus::Active,
        })
        .collect::<Vec<_>>();
    let ignored_existing = snapshots
        .iter()
        .map(|snapshot| (MemberStatus::Incoming, snapshot.member_handle.clone()))
        .collect::<Vec<_>>();
    check_workspace_member_kid_uniqueness(
        workspace_path,
        &candidates,
        &ignored_existing,
        &[MemberStatus::Active, MemberStatus::Incoming],
    )
}
