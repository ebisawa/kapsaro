// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Promotion of incoming workspace members to active status.
//! Holds a directory lock on members/ to prevent concurrent promotion races.

use super::paths::{
    ensure_members_root_at, member_file_name, open_optional_members_dir_at, open_status_dir_at,
    MemberStatus,
};
use super::store::{enforce_workspace_member_kid_uniqueness_in_open_dirs, MemberKidCandidate};
use crate::support::fs::lock;
use crate::support::fs::read::load_capped_bytes;
use crate::support::fs::relative::{
    ensure_text_file_content_matches_at, open_regular_file_at, regular_file_exists_at,
    remove_file_at, save_text_at, save_text_noreplace_at, DirectoryFd, OpenDir, RemovedEntry,
};
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::post_write::{format_post_change_failure, CompletedChange};
use crate::{Error, Result};

/// What `members/active/<handle>.json` held when the promotion was reviewed.
///
/// An absence is as much part of the review as any content: a document that
/// appears afterwards was never seen, and promoting over it would destroy a
/// change nobody approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionDestinationState {
    Missing,
    Present(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMemberPromotionSnapshot {
    pub member_handle: String,
    pub kid: String,
    pub source_content: String,
    pub destination: PromotionDestinationState,
}

/// Record what the active document for a member holds right now.
///
/// The workspace arrives as the descriptor the command bound to, so what the
/// review recorded and what the promotion later checks come from one tree.
pub fn capture_promotion_destination_at<D>(
    workspace: &D,
    member_handle: &str,
) -> Result<PromotionDestinationState>
where
    D: DirectoryFd,
{
    let Some(active_dir) = open_optional_members_dir_at(workspace, MemberStatus::Active)? else {
        return Ok(PromotionDestinationState::Missing);
    };
    load_destination_state(&active_dir, &member_file_name(member_handle))
}

/// Promote every reviewed member through the workspace the review was made in.
///
/// The descriptor is the one the review captured its snapshots against. Opening
/// the workspace path again here would let a path repointed between the review
/// and the confirmation promote into another workspace, where the snapshots
/// would be checked against documents nobody looked at.
pub fn promote_snapshotted_incoming_members_at<D>(
    workspace: &D,
    snapshots: &[IncomingMemberPromotionSnapshot],
) -> Result<Vec<String>>
where
    D: DirectoryFd,
{
    if snapshots.is_empty() {
        return Ok(Vec::new());
    }

    // Ensure the members/ directory exists before attempting to lock it.
    let members_root = ensure_members_root_at(workspace)?;

    lock::with_exclusive_locked_directory(&members_root, |members_dir| {
        let incoming_dir = open_status_dir_at(members_dir, MemberStatus::Incoming)?;
        let active_dir = open_status_dir_at(members_dir, MemberStatus::Active)?;
        run_post_open_member_dirs_hook();
        ensure_promotion_snapshots_hold(&incoming_dir, &active_dir, snapshots)?;
        ensure_snapshotted_promotion_kids_are_unique(&active_dir, &incoming_dir, snapshots)?;

        // Checking the whole batch first narrows the window in which a batch can
        // be left half applied; it does not close it. A write or an unlink that
        // fails partway through leaves the members before it promoted and the
        // rest where they were. The lock rules out a competing command, so what
        // remains is the filesystem itself failing, and rolling back would add
        // its own way to fail on top of the failure being reported.
        for snapshot in snapshots {
            promote_snapshotted_member(&incoming_dir, &active_dir, snapshot)?;
        }

        Ok(snapshots
            .iter()
            .map(|snapshot| snapshot.member_handle.clone())
            .collect())
    })
}

/// Confirm every source and destination still holds what the review accepted.
///
/// The whole batch is checked before the first document moves, so a promotion
/// that would overwrite a changed active document leaves the workspace exactly
/// as it found it rather than half promoted.
fn ensure_promotion_snapshots_hold(
    incoming_dir: &OpenDir,
    active_dir: &OpenDir,
    snapshots: &[IncomingMemberPromotionSnapshot],
) -> Result<()> {
    for snapshot in snapshots {
        let file_name = member_file_name(&snapshot.member_handle);
        ensure_text_file_content_matches_at(
            incoming_dir,
            &file_name,
            Some(&snapshot.source_content),
            &format!("Incoming member '{}'", snapshot.member_handle),
            MAX_JSON_DOCUMENT_READ_SIZE,
        )?;
        ensure_destination_matches(active_dir, &file_name, snapshot)?;
    }
    Ok(())
}

fn ensure_destination_matches(
    active_dir: &OpenDir,
    file_name: &str,
    snapshot: &IncomingMemberPromotionSnapshot,
) -> Result<()> {
    if load_destination_state(active_dir, file_name)? == snapshot.destination {
        return Ok(());
    }
    Err(Error::build_invalid_operation_error(format!(
        "Active member '{}' changed since review and must be reviewed again.",
        snapshot.member_handle
    )))
}

fn load_destination_state<D>(dir: &D, file_name: &str) -> Result<PromotionDestinationState>
where
    D: DirectoryFd,
{
    if !regular_file_exists_at(dir, file_name)? {
        return Ok(PromotionDestinationState::Missing);
    }
    let display = format_path_relative_to_cwd(&dir.path().join(file_name));
    let mut file = open_regular_file_at(dir, file_name)?;
    let bytes = load_capped_bytes(
        &mut file,
        MAX_JSON_DOCUMENT_READ_SIZE,
        "PublicKey file",
        &display,
    )?;
    Ok(PromotionDestinationState::Present(bytes))
}

fn promote_snapshotted_member(
    incoming_dir: &OpenDir,
    active_dir: &OpenDir,
    snapshot: &IncomingMemberPromotionSnapshot,
) -> Result<()> {
    let file_name = member_file_name(&snapshot.member_handle);
    match snapshot.destination {
        // A member new to active/ must not take over a name something else
        // created since the review, so the write refuses to replace an entry.
        PromotionDestinationState::Missing => {
            save_text_noreplace_at(active_dir, &file_name, &snapshot.source_content)?
        }
        PromotionDestinationState::Present(_) => {
            save_text_at(active_dir, &file_name, &snapshot.source_content)?
        }
    }
    report_incoming_cleanup(incoming_dir, &file_name, &snapshot.member_handle)
}

/// Report what became of the incoming document the promotion cleaned up.
///
/// The unlink is the point the name stops resolving, so a sync that failed after
/// it leaves the document gone and only its durability in question. Saying only
/// that the cleanup failed would send an operator looking for a document that is
/// no longer there.
fn report_incoming_cleanup(
    incoming_dir: &OpenDir,
    file_name: &str,
    member_handle: &str,
) -> Result<()> {
    let removed = remove_file_at(incoming_dir, file_name).map_err(|error| {
        Error::build_io_error(format!(
            "Failed to clean incoming member '{}': {}",
            member_handle,
            error.format_user_message()
        ))
    })?;
    match removed {
        RemovedEntry::Persisted => Ok(()),
        RemovedEntry::Unpersisted(error) => Err(Error::build_io_error(format_post_change_failure(
            "The incoming member document",
            &incoming_dir.path().join(file_name),
            CompletedChange::Removed,
            "its directory entry was not persisted, so a crash before the next sync could bring \
             it back",
            error.format_user_message(),
        ))),
    }
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
    enforce_workspace_member_kid_uniqueness_in_open_dirs(
        active_dir,
        incoming_dir,
        &candidates,
        &ignored_existing,
    )
}

// Fault-injection seam: runs inside the members/ lock once both status
// directories are open, which is the only window in which the paths they were
// opened through can be repointed under a running promotion. Only a call point
// in the production flow reaches that window, so the seam lives here and
// compiles out of production builds.
#[cfg(test)]
thread_local! {
    static POST_OPEN_MEMBER_DIRS_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_post_open_member_dirs_hook() {
    POST_OPEN_MEMBER_DIRS_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_post_open_member_dirs_hook() {}

#[cfg(test)]
pub(crate) fn set_post_open_member_dirs_hook(hook: impl FnOnce() + 'static) {
    POST_OPEN_MEMBER_DIRS_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_workspace_members_promotion_test.rs"]
mod io_workspace_members_promotion_test;
