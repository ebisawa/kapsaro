// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Identity-bound deletion of one stored local trust store document.
//! Moves the confirmed document aside and unlinks only what answers as that document.

use crate::support::fs::relative::{
    remove_file_at, rename_child_noreplace_unsynced_at, sync_directory_at,
    unique_write_staging_name, DirectoryFd, RemovedEntry,
};
use crate::support::fs::snapshot::RegularFileSnapshot;
use crate::support::path::{format_finding_path, format_path_relative_to_cwd};
use crate::support::post_write::{format_post_change_failure, CompletedChange};
use crate::{Error, Result};
use std::path::Path;

/// Delete the document the confirmation just accepted, and say whether it went.
///
/// `unlinkat` names a directory entry rather than an inode, so a name repointed
/// between the confirmation and the deletion would destroy a document the
/// operator never saw. The entry is moved aside first and identified from the
/// descriptor the confirmation holds, and only a document that answers as the
/// confirmed one is unlinked.
pub(crate) fn remove_confirmed_trust_store<D>(
    locked_trust_dir: &D,
    file_name: &str,
    confirmed: Option<RegularFileSnapshot>,
    path: &Path,
) -> Result<bool>
where
    D: DirectoryFd,
{
    let Some(confirmed) = confirmed else {
        return Ok(false);
    };
    if !confirmed.still_holds(locked_trust_dir, file_name)? {
        return Err(build_confirmation_changed_error(path));
    }
    let quarantine =
        quarantine_confirmed_trust_store(locked_trust_dir, file_name, &confirmed, path)?;
    let removal = remove_file_at(locked_trust_dir, &quarantine);
    report_quarantined_removal(locked_trust_dir, &quarantine, path, file_name, removal)
}

/// Turn the outcome of the unlink into the answer the reset reports.
///
/// The removal says for itself whether the unlink landed, so nothing here looks
/// the entry up again to find out. An error is the unlink's own and leaves the
/// document standing under the name it was moved to; a sync that failed after it
/// leaves the deletion done and only its durability in question.
fn report_quarantined_removal<D>(
    locked_trust_dir: &D,
    quarantine: &str,
    path: &Path,
    file_name: &str,
    removal: Result<RemovedEntry>,
) -> Result<bool>
where
    D: DirectoryFd,
{
    match removal {
        Ok(RemovedEntry::Persisted) => Ok(true),
        Ok(RemovedEntry::Unpersisted(error)) => Err(Error::build_io_error(
            format_failure_after_trust_store_removal(
                path,
                "its directory entry was not persisted",
                &error,
            ),
        )),
        Err(error) => Err(build_undeleted_store_error(
            locked_trust_dir,
            quarantine,
            path,
            file_name,
            &error,
        )),
    }
}

/// Say that the store went before naming what went wrong afterwards.
///
/// The deletion is what the operator asked for and it landed. Reporting only
/// the failure that followed reads as "the reset did not happen", which sends
/// them looking for approvals that are already gone.
pub(crate) fn format_failure_after_trust_store_removal(
    path: &Path,
    condition: &str,
    error: &Error,
) -> String {
    format_post_change_failure(
        "The local trust store",
        path,
        CompletedChange::Removed,
        condition,
        error.format_user_message(),
    )
}

/// Move the confirmed document to a name of this run's own, and prove the move
/// took the document the confirmation accepted.
///
/// The rename is addressed by name and races a concurrent replacement exactly
/// as the unlink would. What it buys is that taking the wrong entry destroys
/// nothing: the entry is still there to be identified, and one that is not the
/// confirmed document goes back under the store's name. The destination is
/// unique to this run and is created without replacing anything, so whatever
/// stands under it afterwards is what this rename moved.
fn quarantine_confirmed_trust_store<D>(
    locked_trust_dir: &D,
    file_name: &str,
    confirmed: &RegularFileSnapshot,
    path: &Path,
) -> Result<String>
where
    D: DirectoryFd,
{
    let quarantine = unique_write_staging_name(file_name);
    run_pre_quarantine_hook();
    rename_child_noreplace_unsynced_at(locked_trust_dir, file_name, &quarantine)
        .map_err(|error| build_quarantine_failed_error(path, &error))?;
    run_post_quarantine_hook();
    let reason = match confirmed.still_holds(locked_trust_dir, &quarantine) {
        Ok(true) => return Ok(quarantine),
        Ok(false) => "another document stood at its name".to_string(),
        Err(error) => format!(
            "what stood at its name could not be identified: {}",
            error.format_user_message()
        ),
    };
    Err(restore_unconfirmed_entry(
        locked_trust_dir,
        file_name,
        &quarantine,
        path,
        &reason,
    ))
}

/// Put back an entry the move took that the confirmation never accepted.
///
/// The entry holds approvals this run has no mandate to destroy, so it goes
/// back under the store's own name and the reset ends having deleted nothing. A
/// restore that cannot land leaves the document under the name it was moved to,
/// and the report names both names, because that entry is the only copy. The
/// trust directory goes on working: an entry under a staging name is skipped by
/// the directory check rather than refused, so later runs read no approvals at
/// all until an operator renames it back, and `doctor` reports it standing
/// there.
fn restore_unconfirmed_entry<D>(
    locked_trust_dir: &D,
    file_name: &str,
    quarantine: &str,
    path: &Path,
    reason: &str,
) -> Error
where
    D: DirectoryFd,
{
    let replaced = format_removal_target_replaced(path, reason);
    if let Err(error) = rename_child_noreplace_unsynced_at(locked_trust_dir, quarantine, file_name)
    {
        return build_unrestored_entry_error(
            locked_trust_dir,
            quarantine,
            file_name,
            &replaced,
            &error,
        );
    }
    if let Err(error) = sync_directory_at(locked_trust_dir) {
        return Error::build_io_error(format!(
            "{replaced}. The document standing there was put back under that name and nothing was \
             deleted, but the directory entry was not persisted: {}",
            error.format_user_message()
        ));
    }
    Error::build_invalid_operation_error(format!(
        "{replaced}. The document standing there was left as it was and nothing was deleted."
    ))
}

/// Report a store that could not be moved aside, which leaves it where it is.
///
/// Nothing has been deleted at this point and nothing will be, so the message
/// says so: a bare rename failure at the end of a reset the operator confirmed
/// reads as though the deletion might have half happened.
fn build_quarantine_failed_error(path: &Path, error: &Error) -> Error {
    Error::build_io_error(format!(
        "Local trust store '{}' could not be moved aside for deletion: {}. Nothing was deleted.",
        format_path_relative_to_cwd(path),
        error.format_user_message()
    ))
}

/// Say that the deletion was aimed at a document that is no longer the target.
fn format_removal_target_replaced(path: &Path, reason: &str) -> String {
    format!(
        "Local trust store '{}' changed since reset confirmation and must be reviewed again: \
         {reason}",
        format_path_relative_to_cwd(path)
    )
}

/// Report the document left under the name the deletion moved it to.
///
/// The entry is the only copy of approvals nobody agreed to discard, so both
/// names are given: the one it is under now, and the one it has to go back to.
fn build_unrestored_entry_error<D>(
    locked_trust_dir: &D,
    quarantine: &str,
    file_name: &str,
    replaced: &str,
    error: &Error,
) -> Error
where
    D: DirectoryFd,
{
    Error::build_io_error(format!(
        "{replaced}. It was not deleted, but it could not be put back under that name: {}. It is \
         at {} and must be renamed to '{file_name}' to be read again.",
        error.format_user_message(),
        format_finding_path(&locked_trust_dir.path().join(quarantine))
    ))
}

fn build_confirmation_changed_error(path: &Path) -> Error {
    Error::build_invalid_operation_error(format!(
        "Local trust store '{}' changed since reset confirmation and must be reviewed again.",
        format_path_relative_to_cwd(path)
    ))
}

/// Report the document the deletion left standing under the name it moved it to.
///
/// A removal that comes back with an error is one whose unlink did not land, so
/// the document is still under the name it was moved to and the report names
/// that entry: the deletion already moved it off the name an operator would
/// look under.
fn build_undeleted_store_error<D>(
    locked_trust_dir: &D,
    quarantine: &str,
    path: &Path,
    file_name: &str,
    error: &Error,
) -> Error
where
    D: DirectoryFd,
{
    Error::build_io_error(format!(
        "Local trust store '{}' was moved aside for deletion but the deletion did not land: {}. It \
         still holds the approvals the reset would have discarded and is at {}; remove that entry \
         to finish the reset, or rename it to '{file_name}' to keep them.",
        format_path_relative_to_cwd(path),
        error.format_user_message(),
        format_finding_path(&locked_trust_dir.path().join(quarantine))
    ))
}

// Fault-injection seams. They bracket the rename that moves the confirmed
// document aside: the first runs once that document has been matched against
// its name, which is the window a concurrent replacement has to slip through,
// and the second runs once the rename has taken whatever stood there, which is
// the only point from which the name can be occupied again before the restore
// tries to give it back. Only a call point inside the production flow reaches
// either window, so the seams live here and compile out of production builds.
#[cfg(test)]
thread_local! {
    static PRE_QUARANTINE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static POST_QUARANTINE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_pre_quarantine_hook() {
    PRE_QUARANTINE_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_pre_quarantine_hook() {}

#[cfg(test)]
fn run_post_quarantine_hook() {
    POST_QUARANTINE_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_post_quarantine_hook() {}

#[cfg(test)]
pub(crate) fn set_pre_quarantine_hook(hook: impl FnOnce() + 'static) {
    PRE_QUARANTINE_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
pub(crate) fn set_post_quarantine_hook(hook: impl FnOnce() + 'static) {
    POST_QUARANTINE_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_trust_remove_test.rs"]
mod io_trust_remove_test;
