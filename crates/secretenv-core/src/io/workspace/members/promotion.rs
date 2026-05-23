// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::paths::{ensure_members_dir, member_file_path, MemberStatus};
use super::store::{check_workspace_member_kid_uniqueness, MemberKidCandidate};
use crate::support::fs::{atomic, ensure_text_file_matches_snapshot_with_limit, lock};
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
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
