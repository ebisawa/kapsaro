// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::support::fs::ensure_dir;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Status of a member in the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    Active,
    Incoming,
}

pub(super) fn members_dir(workspace_path: &Path, status: MemberStatus) -> PathBuf {
    match status {
        MemberStatus::Active => workspace_path.join("members/active"),
        MemberStatus::Incoming => workspace_path.join("members/incoming"),
    }
}

pub(super) fn member_file_path(
    workspace_path: &Path,
    status: MemberStatus,
    member_handle: &str,
) -> PathBuf {
    members_dir(workspace_path, status).join(format!("{}.json", member_handle))
}

pub(super) fn ensure_members_dir(workspace_path: &Path, status: MemberStatus) -> Result<PathBuf> {
    let dir = members_dir(workspace_path, status);
    ensure_dir(&dir).map_err(|e| {
        Error::build_io_error(format!(
            "Failed to create {} directory: {}",
            format_path_relative_to_cwd(&dir),
            e
        ))
    })?;
    Ok(dir)
}

pub(super) fn find_member_path(
    workspace_path: &Path,
    member_handle: &str,
) -> Option<(PathBuf, MemberStatus)> {
    [MemberStatus::Active, MemberStatus::Incoming]
        .into_iter()
        .find_map(|status| {
            let path = member_file_path(workspace_path, status, member_handle);
            path.exists().then_some((path, status))
        })
}

/// Return the path to a member file in the active/ directory.
pub fn get_active_member_file_path(workspace_path: &Path, member_handle: &str) -> PathBuf {
    member_file_path(workspace_path, MemberStatus::Active, member_handle)
}

/// Return the path to a member file in the incoming/ directory.
pub fn get_incoming_member_file_path(workspace_path: &Path, member_handle: &str) -> PathBuf {
    member_file_path(workspace_path, MemberStatus::Incoming, member_handle)
}
