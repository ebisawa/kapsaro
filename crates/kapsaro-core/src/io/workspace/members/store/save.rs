// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Writing member documents into a workspace.
//! Stages each document beside its name and publishes it with a rename on one directory descriptor.

use super::super::paths::{
    ensure_members_root_at, member_file_name, open_status_dir_at, status_dir_name, MemberStatus,
};
use super::uniqueness::ensure_member_document_kid_is_unique_in_open_dirs;
use crate::format::schema::document::parse_public_key_str;
use crate::support::fs::lock::with_exclusive_locked_directory;
use crate::support::fs::relative::{
    format_unreplaceable_child_type, optional_child_type_at, save_text_at, ChildType, DirectoryFd,
    OpenDir,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

/// What one save found standing at the name it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberDocumentWrite {
    /// The name was free and the document was written.
    Created,
    /// A document stood there and this one replaced it.
    Replaced,
    /// A document stood there and the save was not allowed to replace it.
    Kept,
}

/// Write one member document into the status directory it belongs in.
///
/// A document already standing at the name is refused, so this is the form for
/// callers that treat one as a failure.
pub fn save_member_content<D>(
    workspace: &D,
    status: MemberStatus,
    member_handle: &str,
    content: &str,
    overwrite: bool,
) -> Result<()>
where
    D: DirectoryFd,
{
    match save_member_content_keeping_existing(
        workspace,
        status,
        member_handle,
        content,
        overwrite,
    )? {
        MemberDocumentWrite::Created | MemberDocumentWrite::Replaced => Ok(()),
        MemberDocumentWrite::Kept => Err(build_member_document_exists_error(status, member_handle)),
    }
}

/// The same write, reporting a document already there instead of refusing.
///
/// The workspace arrives as the descriptor the caller selected, and `members/`
/// is a single named child of it, so the lock fixes the member set the caller
/// chose rather than whatever the workspace path names by the time the write
/// runs. The kid uniqueness check and the write then run under that one lock and
/// both address the descriptors it opened: a check made through a fresh path
/// resolution would judge a member set that the write need not land in. The same
/// lock settles whether the name was free, so a caller that tells a creation
/// from a replacement is told what the write actually did rather than what a
/// separate look at the path said beforehand.
pub fn save_member_content_keeping_existing<D>(
    workspace: &D,
    status: MemberStatus,
    member_handle: &str,
    content: &str,
    overwrite: bool,
) -> Result<MemberDocumentWrite>
where
    D: DirectoryFd,
{
    let source_name = format!("member content for {}", member_handle);
    let public_key = parse_public_key_str(content, &source_name)?;
    let members_root = ensure_members_root_at(workspace)?;
    let request = MemberDocumentWriteRequest {
        status,
        member_handle,
        content,
        kid: &public_key.protected.kid,
        overwrite,
    };

    with_exclusive_locked_directory(&members_root, |members_dir| {
        let active_dir = open_status_dir_at(members_dir, MemberStatus::Active)?;
        let incoming_dir = open_status_dir_at(members_dir, MemberStatus::Incoming)?;
        run_post_open_save_dirs_hook();
        save_member_document_locked(&active_dir, &incoming_dir, &request)
    })
}

/// One member document a save is about to write.
struct MemberDocumentWriteRequest<'a> {
    status: MemberStatus,
    member_handle: &'a str,
    content: &'a str,
    kid: &'a str,
    overwrite: bool,
}

/// Judge the name and the kid against the directories the lock opened, then
/// write.
fn save_member_document_locked(
    active_dir: &OpenDir,
    incoming_dir: &OpenDir,
    request: &MemberDocumentWriteRequest<'_>,
) -> Result<MemberDocumentWrite> {
    let dir = match request.status {
        MemberStatus::Active => active_dir,
        MemberStatus::Incoming => incoming_dir,
    };
    let file_name = member_file_name(request.member_handle);
    let existing = optional_child_type_at(dir, &file_name)?;
    enforce_replaceable_child_type(dir, &file_name, existing)?;
    if existing.is_some() && !request.overwrite {
        return Ok(MemberDocumentWrite::Kept);
    }
    ensure_member_document_kid_is_unique_in_open_dirs(
        active_dir,
        incoming_dir,
        request.status,
        request.member_handle,
        request.kid,
        existing.is_some(),
    )?;
    save_text_at(dir, &file_name, request.content)?;
    Ok(match existing {
        Some(_) => MemberDocumentWrite::Replaced,
        None => MemberDocumentWrite::Created,
    })
}

/// Refuse a name the write must not take over.
///
/// An entry that is not a regular file is not a document kapsaro wrote, and the
/// rename that publishes the write would replace it: the link or directory
/// standing there is the only sign the name was repointed, so it is reported
/// rather than erased.
fn enforce_replaceable_child_type(
    dir: &OpenDir,
    file_name: &str,
    existing: Option<ChildType>,
) -> Result<()> {
    let Some(description) = existing.and_then(format_unreplaceable_child_type) else {
        return Ok(());
    };
    Err(Error::build_invalid_operation_error(format!(
        "refusing to replace {} standing where a member document belongs: {}",
        description,
        format_path_relative_to_cwd(&dir.path().join(file_name))
    )))
}

/// Report a member document the save was not allowed to replace.
fn build_member_document_exists_error(status: MemberStatus, member_handle: &str) -> Error {
    Error::build_invalid_operation_error(format!(
        "Member '{}' already exists in {}/ (use --force to overwrite)",
        member_handle,
        status_dir_name(status)
    ))
}

// Fault-injection seam: runs inside the members/ lock once both status
// directories are open, which is the only window in which the paths they were
// opened through can be repointed under a running save. Only a call point in
// the production flow reaches that window, so the seam lives here and compiles
// out of production builds.
#[cfg(test)]
thread_local! {
    static POST_OPEN_SAVE_DIRS_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_post_open_save_dirs_hook() {
    POST_OPEN_SAVE_DIRS_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_post_open_save_dirs_hook() {}

#[cfg(test)]
pub(crate) fn set_post_open_save_dirs_hook(hook: impl FnOnce() + 'static) {
    POST_OPEN_SAVE_DIRS_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}
