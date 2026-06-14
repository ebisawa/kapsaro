// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Promotion of incoming workspace members to active status.
//! Holds a directory lock on members/ to prevent concurrent promotion races.

use super::paths::{ensure_members_dir, MemberStatus};
use super::store::{check_workspace_member_kid_uniqueness_in_open_dirs, MemberKidCandidate};
use crate::support::fs::lock;
use crate::support::fs::relative::{
    ensure_text_file_matches_snapshot_with_limit_at, remove_file_at, save_text_at, OpenDir,
};
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMemberPromotionSnapshot {
    pub member_handle: String,
    pub kid: String,
    pub source_path: PathBuf,
    pub source_content: String,
}

pub fn promote_snapshotted_incoming_members(
    workspace_path: &Path,
    snapshots: &[IncomingMemberPromotionSnapshot],
) -> Result<Vec<String>> {
    if snapshots.is_empty() {
        return Ok(Vec::new());
    }

    // Ensure the members/ directory exists before attempting to lock it.
    ensure_members_dir(workspace_path, MemberStatus::Active)?;

    let members_root = workspace_path.join("members");
    lock::with_locked_dir(&members_root, |members_dir| {
        let incoming_dir = members_dir.open_child_dir("incoming")?;
        let active_dir = members_dir.open_child_dir("active")?;
        ensure_snapshotted_promotion_kids_are_unique(&active_dir, &incoming_dir, snapshots)?;

        for snapshot in snapshots {
            promote_snapshotted_member(&incoming_dir, &active_dir, snapshot)?;
        }

        Ok(snapshots
            .iter()
            .map(|snapshot| snapshot.member_handle.clone())
            .collect())
    })
}

fn promote_snapshotted_member(
    incoming_dir: &OpenDir,
    active_dir: &OpenDir,
    snapshot: &IncomingMemberPromotionSnapshot,
) -> Result<()> {
    let member_file_name = member_file_name(&snapshot.member_handle);
    let subject_display = format!("Incoming member '{}'", snapshot.member_handle);
    ensure_text_file_matches_snapshot_with_limit_at(
        incoming_dir,
        &member_file_name,
        Some(&snapshot.source_content),
        &subject_display,
        MAX_JSON_DOCUMENT_READ_SIZE,
    )?;
    save_text_at(active_dir, &member_file_name, &snapshot.source_content)?;
    remove_file_at(incoming_dir, &member_file_name).map_err(|e| {
        Error::build_io_error(format!(
            "Failed to clean incoming member '{}': {}",
            snapshot.member_handle, e
        ))
    })
}

fn member_file_name(member_handle: &str) -> String {
    format!("{}.json", member_handle)
}

fn ensure_snapshotted_promotion_kids_are_unique(
    active_dir: &OpenDir,
    incoming_dir: &OpenDir,
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
    check_workspace_member_kid_uniqueness_in_open_dirs(
        active_dir,
        incoming_dir,
        &candidates,
        &ignored_existing,
    )
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_workspace_members_promotion_test.rs"]
mod io_workspace_members_promotion_test;
