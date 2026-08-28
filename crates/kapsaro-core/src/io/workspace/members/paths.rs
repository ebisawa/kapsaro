// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace member locations and the directories that hold them.
//! Opens each status directory as the descriptor the member store operates on.

use crate::support::fs::relative::{
    ensure_child_dir_at, open_child_dir, open_dir_nofollow, open_optional_child_dir, DirectoryFd,
    DirectoryScope, OpenDir,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

/// Status of a member in the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    Active,
    Incoming,
}

pub(super) fn members_dir(workspace_path: &Path, status: MemberStatus) -> PathBuf {
    workspace_path
        .join(MEMBERS_DIR_NAME)
        .join(status_dir_name(status))
}

/// Name of the workspace member registry directory.
pub(crate) const MEMBERS_DIR_NAME: &str = "members";

/// Name of the directory holding the members the workspace has accepted.
pub(crate) const ACTIVE_DIR_NAME: &str = "active";

/// Name of the directory holding the members still awaiting review.
pub(crate) const INCOMING_DIR_NAME: &str = "incoming";

/// The directory one membership status lives in.
///
/// Every caller that names a status directory goes through here, so the two
/// spellings exist once and a rename cannot leave one caller behind.
pub(crate) fn status_dir_name(status: MemberStatus) -> &'static str {
    match status {
        MemberStatus::Active => ACTIVE_DIR_NAME,
        MemberStatus::Incoming => INCOMING_DIR_NAME,
    }
}

/// Extension every member document name carries.
const MEMBER_DOCUMENT_EXTENSION: &str = "json";

pub(super) fn member_file_name(member_handle: &str) -> String {
    format!("{}.{}", member_handle, MEMBER_DOCUMENT_EXTENSION)
}

/// Whether a name is spelled the way a member document is spelled.
///
/// Every caller that judges an entry by its extension goes through here, so the
/// one spelling exists once and a listing cannot drift from a write.
pub(crate) fn has_member_document_extension(name: &str) -> bool {
    Path::new(name).extension().and_then(|ext| ext.to_str()) == Some(MEMBER_DOCUMENT_EXTENSION)
}

pub(super) fn member_file_path(
    workspace_path: &Path,
    status: MemberStatus,
    member_handle: &str,
) -> PathBuf {
    members_dir(workspace_path, status).join(member_file_name(member_handle))
}

/// Open the directory a status lives in, reporting nothing when it is absent.
///
/// A link in the final position is refused rather than followed: every member
/// document is addressed relative to this descriptor, so the one step that must
/// stay inside the workspace is the step that produces it.
pub(super) fn open_optional_members_dir(
    workspace_path: &Path,
    status: MemberStatus,
) -> Result<Option<OpenDir>> {
    match open_dir_nofollow(
        &members_dir(workspace_path, status),
        DirectoryScope::Generic,
    ) {
        Ok(dir) => Ok(Some(dir)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Open the `members/` root under a workspace descriptor, reporting nothing when
/// it is absent.
///
/// The root is what every member mutation locks, so a caller that is about to
/// take that lock reaches it through the workspace descriptor it bound to rather
/// than by resolving the path again.
pub(super) fn open_optional_members_root_at<D>(workspace: &D) -> Result<Option<OpenDir>>
where
    D: DirectoryFd,
{
    open_optional_child_dir(workspace, MEMBERS_DIR_NAME)
}

/// Open one status directory below an already opened `members/` root, reporting
/// nothing when it is absent.
pub(super) fn open_optional_status_dir_at<D>(
    members_root: &D,
    status: MemberStatus,
) -> Result<Option<OpenDir>>
where
    D: DirectoryFd,
{
    open_optional_child_dir(members_root, status_dir_name(status))
}

/// Open one status directory below an already opened `members/` root.
pub(super) fn open_status_dir_at<D>(members_root: &D, status: MemberStatus) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    open_child_dir(members_root, status_dir_name(status))
}

/// Open the directory a status lives in under a workspace descriptor.
///
/// Every step is a single named child of the workspace the command bound to,
/// and a link in any of them is refused rather than followed. A workspace path
/// repointed while the command runs therefore cannot move the member set a read
/// is authorized against.
pub(super) fn open_optional_members_dir_at<D>(
    workspace: &D,
    status: MemberStatus,
) -> Result<Option<OpenDir>>
where
    D: DirectoryFd,
{
    let Some(members) = open_optional_members_root_at(workspace)? else {
        return Ok(None);
    };
    open_optional_status_dir_at(&members, status)
}

/// Create `members/` with both status directories under a workspace descriptor,
/// and hand back the root that holds them.
///
/// The root is what a save and a promotion lock, so it travels back with the
/// descriptor it was built from rather than being resolved from the workspace
/// path again: two resolutions of the same name can reach two directories. Both
/// status directories are created together because every mutation reads the pair
/// under one lock to judge the key identifiers the workspace already carries.
pub(super) fn ensure_members_root_at<D>(workspace: &D) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    let members = ensure_child_dir_at(workspace, MEMBERS_DIR_NAME)?;
    ensure_child_dir_at(&members, ACTIVE_DIR_NAME)?;
    ensure_child_dir_at(&members, INCOMING_DIR_NAME)?;
    Ok(members)
}

/// Open the directory holding a member document named by its full path.
pub(super) fn open_member_document_parent(path: &Path) -> Result<(OpenDir, String)> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::build_invalid_argument_error(format!(
                "Member file has no readable name: {}",
                format_path_relative_to_cwd(path)
            ))
        })?
        .to_string();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = open_dir_nofollow(parent, DirectoryScope::Generic)?;
    Ok((dir, name))
}

/// Return the path to a member file in the active/ directory.
pub fn get_active_member_file_path(workspace_path: &Path, member_handle: &str) -> PathBuf {
    member_file_path(workspace_path, MemberStatus::Active, member_handle)
}

/// Return the path to a member file in the incoming/ directory.
pub fn get_incoming_member_file_path(workspace_path: &Path, member_handle: &str) -> PathBuf {
    member_file_path(workspace_path, MemberStatus::Incoming, member_handle)
}
