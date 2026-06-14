// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Promotion of incoming workspace members to active status.
//! Holds a directory lock on members/ to prevent concurrent promotion races.

use super::paths::{ensure_members_dir, member_file_path, MemberStatus};
use super::store::{check_workspace_member_kid_uniqueness, MemberKidCandidate};
use crate::support::fs::policy::{ensure_real_directory_tree, DirectoryMode, DirectoryPurpose};
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

    // Ensure the members/ directory exists before attempting to lock it.
    ensure_members_dir(workspace_path, MemberStatus::Active)?;

    let members_root = workspace_path.join("members");
    lock::with_dir_lock(&members_root, || {
        // Re-validate the incoming directory under the lock before any read or
        // remove. A symlink swapped in for `incoming/` after the review snapshot
        // must not let the source read/remove escape the workspace.
        enforce_real_incoming_dir(&members_root)?;
        ensure_snapshotted_promotion_kids_are_unique(workspace_path, snapshots)?;

        for snapshot in snapshots {
            promote_snapshotted_member(workspace_path, snapshot)?;
        }

        Ok(snapshots
            .iter()
            .map(|snapshot| snapshot.member_handle.clone())
            .collect())
    })
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
}

fn enforce_real_incoming_dir(members_root: &Path) -> Result<()> {
    let incoming_dir = members_root.join("incoming");
    ensure_real_directory_tree(
        &incoming_dir,
        DirectoryPurpose::Workspace,
        DirectoryMode::Normal,
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

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_workspace_members_promotion_test.rs"]
mod io_workspace_members_promotion_test;
