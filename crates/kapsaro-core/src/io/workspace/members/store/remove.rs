// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Removal of an active member document.
//! Quarantines and verifies the reviewed document before unlinking it.

use super::super::paths::{
    member_file_name, open_optional_members_root_at, open_optional_status_dir_at,
    open_status_dir_at, MemberStatus,
};
use crate::support::fs::lock::with_exclusive_locked_directory;
use crate::support::fs::relative::{
    open_dir_identity, remove_file_at, rename_child_noreplace_unsynced_at, sync_directory_at,
    unique_write_staging_name, DirectoryFd, OpenDir, RemovedEntry,
};
use crate::support::fs::snapshot::{load_optional_regular_file_snapshot_at, RegularFileSnapshot};
use crate::support::path::format_finding_path;
use crate::support::post_write::{format_post_change_failure, CompletedChange};
use crate::{Error, Result};
use std::sync::Arc;

/// The active member document one removal was reviewed against.
///
/// The `members/` root is held open because that is the directory every member
/// mutation locks, and the `active/` directory below it is held open with the
/// document's identity, so the removal that follows a confirmation prompt acts
/// on the entry the operator was shown rather than on whatever the name resolves
/// to by then.
#[derive(Debug)]
pub struct ReviewedMemberDocument {
    members_root: Arc<OpenDir>,
    active_dir: Arc<OpenDir>,
    member_handle: String,
    reviewed: RegularFileSnapshot,
}

/// Read the active document for one member and hold what the review saw.
///
/// The workspace arrives as the descriptor the command bound to, and `members/`
/// and `active/` are opened as single named children of it, so the document this
/// reads and the one the removal unlinks come from one tree.
pub fn review_active_member_document<D>(
    workspace: &D,
    member_handle: &str,
) -> Result<ReviewedMemberDocument>
where
    D: DirectoryFd,
{
    let Some(members_root) = open_optional_members_root_at(workspace)? else {
        return Err(missing_active_member_error(member_handle));
    };
    let Some(active_dir) = open_optional_status_dir_at(&members_root, MemberStatus::Active)? else {
        return Err(missing_active_member_error(member_handle));
    };
    let file_name = member_file_name(member_handle);
    let Some(reviewed) = load_optional_regular_file_snapshot_at(&active_dir, &file_name)? else {
        return Err(missing_active_member_error(member_handle));
    };
    Ok(ReviewedMemberDocument {
        members_root: Arc::new(members_root),
        active_dir: Arc::new(active_dir),
        member_handle: member_handle.to_string(),
        reviewed,
    })
}

impl ReviewedMemberDocument {
    /// Delete the document this review holds, refusing one that has moved.
    ///
    /// The lock is taken on `members/` rather than on `active/`, because that is
    /// the directory a promotion locks: `flock` arbitrates per inode, so a
    /// removal holding only `active/` would exclude nobody and a promotion could
    /// write the document back between the check below and the unlink, leaving
    /// both commands reporting success and the approved removal undone.
    ///
    /// Under that lock the name is re-checked against the reviewed inode and
    /// bytes. The entry is then quarantined and checked again, so a document
    /// replaced between comparison and unlink remains available for recovery.
    pub fn remove(&self) -> Result<()> {
        let file_name = member_file_name(&self.member_handle);
        with_exclusive_locked_directory(self.members_root.as_ref(), |members_dir| {
            let active_dir = open_status_dir_at(members_dir, MemberStatus::Active)?;
            self.ensure_reviewed_active_directory(&active_dir)?;
            if !self.reviewed.still_holds(&active_dir, &file_name)? {
                return Err(self.changed_since_review_error());
            }
            let quarantine = self.quarantine_reviewed_document(&active_dir, &file_name)?;
            report_quarantined_member_removal(
                &active_dir,
                &file_name,
                &quarantine,
                remove_file_at(&active_dir, &quarantine),
            )
        })
    }

    /// Move the named entry aside and verify the move took the reviewed bytes.
    fn quarantine_reviewed_document(
        &self,
        active_dir: &OpenDir,
        file_name: &str,
    ) -> Result<String> {
        let quarantine = unique_write_staging_name(file_name);
        run_member_pre_quarantine_hook();
        rename_child_noreplace_unsynced_at(active_dir, file_name, &quarantine)
            .map_err(|error| quarantine_failed_error(active_dir, file_name, &error))?;
        run_member_post_quarantine_hook();
        match self.reviewed.still_holds(active_dir, &quarantine) {
            Ok(true) => Ok(quarantine),
            Ok(false) => Err(self.restore_unreviewed_document(
                active_dir,
                file_name,
                &quarantine,
                "another document stood at its name",
            )),
            Err(error) => Err(self.restore_unreviewed_document(
                active_dir,
                file_name,
                &quarantine,
                &format!(
                    "the moved entry could not be identified: {}",
                    error.format_user_message()
                ),
            )),
        }
    }

    /// Restore an entry the review did not authorize this removal to delete.
    fn restore_unreviewed_document(
        &self,
        active_dir: &OpenDir,
        file_name: &str,
        quarantine: &str,
        reason: &str,
    ) -> Error {
        let changed = format!(
            "Active member '{}' changed since review and must be reviewed again: {reason}",
            self.member_handle
        );
        if let Err(error) = rename_child_noreplace_unsynced_at(active_dir, quarantine, file_name) {
            return unrestored_member_document_error(
                active_dir, file_name, quarantine, &changed, &error,
            );
        }
        match sync_directory_at(active_dir) {
            Ok(()) => Error::build_invalid_operation_error(format!(
                "{changed}. The document was restored under its original name and nothing was deleted."
            )),
            Err(error) => Error::build_io_error(format!(
                "{changed}. The document was restored under its original name and nothing was deleted, but the directory entry was not persisted: {}",
                error.format_user_message()
            )),
        }
    }

    /// Refuse a removal whose `active/` is no longer the reviewed directory.
    ///
    /// The lock fixes `members/`, so the name below it can still have been
    /// repointed since the review. Comparing the two descriptors keeps the
    /// unlink inside the tree the operator was shown even where the document
    /// itself would pass the identity check, which a hard link to it would.
    fn ensure_reviewed_active_directory(&self, locked_active: &OpenDir) -> Result<()> {
        if open_dir_identity(self.active_dir.as_ref())? == open_dir_identity(locked_active)? {
            return Ok(());
        }
        Err(self.changed_since_review_error())
    }

    fn changed_since_review_error(&self) -> Error {
        Error::build_invalid_operation_error(format!(
            "Active member '{}' changed since review and must be reviewed again.",
            self.member_handle
        ))
    }
}

fn report_quarantined_member_removal(
    active_dir: &OpenDir,
    file_name: &str,
    quarantine: &str,
    removal: Result<RemovedEntry>,
) -> Result<()> {
    match removal {
        Ok(RemovedEntry::Persisted) => Ok(()),
        Ok(RemovedEntry::Unpersisted(error)) => {
            Err(unpersisted_removal_error(active_dir, file_name, &error))
        }
        Err(error) => Err(undeleted_member_document_error(
            active_dir, file_name, quarantine, &error,
        )),
    }
}

fn quarantine_failed_error(active_dir: &OpenDir, file_name: &str, error: &Error) -> Error {
    Error::build_io_error(format!(
        "Active member document '{}' could not be moved aside for deletion: {}. Nothing was deleted.",
        format_finding_path(&active_dir.path().join(file_name)),
        error.format_user_message()
    ))
}

fn unrestored_member_document_error(
    active_dir: &OpenDir,
    file_name: &str,
    quarantine: &str,
    changed: &str,
    error: &Error,
) -> Error {
    Error::build_io_error(format!(
        "{changed}. The document was not deleted, but it could not be restored under its original name: {}. It remains at {}. Preserve or move the entry currently named '{file_name}', then rename the quarantined document to '{file_name}' and review the removal again.",
        error.format_user_message(),
        format_finding_path(&active_dir.path().join(quarantine))
    ))
}

fn undeleted_member_document_error(
    active_dir: &OpenDir,
    file_name: &str,
    quarantine: &str,
    error: &Error,
) -> Error {
    Error::build_io_error(format!(
        "Active member document '{}' was moved aside for deletion, but deletion failed: {}. It remains at {}; remove that entry to finish the removal, or rename it to '{file_name}' to restore the member document.",
        format_finding_path(&active_dir.path().join(file_name)),
        error.format_user_message(),
        format_finding_path(&active_dir.path().join(quarantine))
    ))
}

/// Report a member document the unlink took but whose directory entry was not
/// persisted.
///
/// The removal is what the caller asked for and it landed. A bare sync failure
/// reads as "the member is still there" and sends the operator to remove one
/// that is already gone.
fn unpersisted_removal_error(active_dir: &OpenDir, file_name: &str, error: &Error) -> Error {
    Error::build_io_error(format_post_change_failure(
        "The active member document",
        &active_dir.path().join(file_name),
        CompletedChange::Removed,
        "its directory entry was not persisted, so a crash before the next sync could bring it \
         back",
        error.format_user_message(),
    ))
}

fn missing_active_member_error(member_handle: &str) -> Error {
    Error::build_not_found_error(format!("Member '{}' not found in active/", member_handle))
}

#[cfg(test)]
thread_local! {
    static MEMBER_PRE_QUARANTINE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static MEMBER_POST_QUARANTINE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_member_pre_quarantine_hook() {
    MEMBER_PRE_QUARANTINE_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_member_pre_quarantine_hook() {}

#[cfg(test)]
fn run_member_post_quarantine_hook() {
    MEMBER_POST_QUARANTINE_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_member_post_quarantine_hook() {}

#[cfg(test)]
pub(crate) fn set_member_pre_quarantine_hook(hook: impl FnOnce() + 'static) {
    MEMBER_PRE_QUARANTINE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
pub(crate) fn set_member_post_quarantine_hook(hook: impl FnOnce() + 'static) {
    MEMBER_POST_QUARANTINE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}
