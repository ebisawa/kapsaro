// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Lock effectiveness diagnostics for the doctor command.
//! Measures what a directory lock actually excludes and reports the consequence.

use std::path::Path;

use crate::app::doctor::types::{DoctorCategory, DoctorCheck, DoctorSubject, LocalStateHome};
use crate::error::LOCK_EXCLUSION_RULE;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock::{probe_directory_lock_exclusion, LockExclusionProbe};
use crate::support::fs::mount::{classify_storage_locality, StorageLocality};
use crate::support::fs::relative::DirectoryFd;
use crate::support::path::format_path_relative_to_cwd;

const LOCAL_STATE_CHECK_ID: &str = "local_state.locking";
const WORKSPACE_CHECK_ID: &str = "workspace.locking";

/// Report what a lock on the local state root excludes.
///
/// The root is opened once and both questions are put to that descriptor, so a
/// name repointed while the check runs cannot move the measurement onto another
/// directory. A root that cannot be opened at all leaves the check unmeasured
/// and carries the reason.
pub(super) fn check_local_state_locking(
    base_dir: &Path,
    home: &LocalStateHome,
) -> Vec<DoctorCheck> {
    let subject = DoctorSubject::Path(format_path_relative_to_cwd(base_dir));
    match home {
        LocalStateHome::Opened(opened) => vec![build_locking_check(
            LOCAL_STATE_CHECK_ID,
            DoctorCategory::LocalState,
            opened,
        )],
        LocalStateHome::Missing => vec![build_unmeasured_check(
            LOCAL_STATE_CHECK_ID,
            DoctorCategory::LocalState,
            subject,
            "local state root does not exist".to_string(),
        )],
        LocalStateHome::Unavailable { reason } => vec![build_unmeasured_check(
            LOCAL_STATE_CHECK_ID,
            DoctorCategory::LocalState,
            subject,
            reason.clone(),
        )],
    }
}

/// Report what a lock on the workspace root excludes.
///
/// Both questions are put to the descriptor the run bound to: the exclusion is
/// observed by opening two more descriptions from it, and where the storage
/// lives is read off the same descriptor. Nothing here resolves the workspace
/// path a second time, so the finding is written against the one workspace the
/// rest of the report describes.
pub(crate) fn check_workspace_locking(workspace: &AnchoredDir) -> Vec<DoctorCheck> {
    vec![build_locking_check(
        WORKSPACE_CHECK_ID,
        DoctorCategory::Workspace,
        workspace,
    )]
}

/// What the measurement says about one directory.
///
/// Nothing here fails the run. A command that writes the directory carries on
/// whatever the answer is, because the write is not held together by the lock,
/// and a diagnosis that stopped the exit code on storage the operator chose on
/// purpose would say more than the measurement supports.
enum LockingOutcome {
    /// A lock excludes every writer that can reach the directory.
    Effective,
    /// A lock leaves some writer unexcluded.
    Weak(WeakLocking),
    /// The measurement could not be made, for the stated reason.
    Unmeasured(String),
}

/// Which writer a lock on the directory fails to exclude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WeakLocking {
    /// Locks work between the processes here, and the storage is served to
    /// other machines as well.
    SharedStorage,
    /// Locks work between the processes here, and where the storage lives could
    /// not be established.
    UnknownStorage,
    /// A second lock was granted while the first was held.
    Ineffective,
    /// The filesystem has no locking to offer.
    Unsupported,
}

fn build_locking_check<D>(id: &'static str, category: DoctorCategory, dir: &D) -> DoctorCheck
where
    D: DirectoryFd,
{
    let subject = DoctorSubject::Path(format_path_relative_to_cwd(dir.path()));
    match judge_locking(dir) {
        LockingOutcome::Effective => DoctorCheck::ok(
            id,
            category,
            subject,
            "Directory locks exclude every writer that can reach the directory",
        ),
        LockingOutcome::Weak(kind) => DoctorCheck::warn_with_reason_and_next_action(
            id,
            category,
            subject,
            weak_locking_message(kind),
            weak_locking_reason(kind),
            weak_locking_next_action(kind),
        )
        .with_rule(Some(LOCK_EXCLUSION_RULE)),
        LockingOutcome::Unmeasured(reason) => build_unmeasured_check(id, category, subject, reason),
    }
}

fn build_unmeasured_check(
    id: &'static str,
    category: DoctorCategory,
    subject: DoctorSubject,
    reason: String,
) -> DoctorCheck {
    DoctorCheck::skip(id, category, subject, "Directory locking was not measured")
        .with_reason(reason)
}

/// Measure the exclusion first, and ask where the storage lives only once the
/// locks have been shown to work at all.
fn judge_locking<D>(dir: &D) -> LockingOutcome
where
    D: DirectoryFd,
{
    match probe_directory_lock_exclusion(dir) {
        LockExclusionProbe::Exclusive => judge_storage(dir),
        LockExclusionProbe::Ineffective => LockingOutcome::Weak(WeakLocking::Ineffective),
        LockExclusionProbe::Unsupported => LockingOutcome::Weak(WeakLocking::Unsupported),
        LockExclusionProbe::Contended => LockingOutcome::Unmeasured(CONTENDED_REASON.to_string()),
        LockExclusionProbe::Unavailable { reason } => LockingOutcome::Unmeasured(reason),
    }
}

/// Exclusion between the processes on this host says nothing about a second
/// host, so the storage decides what the working lock is worth.
fn judge_storage<D>(dir: &D) -> LockingOutcome
where
    D: DirectoryFd,
{
    match classify_storage_locality(dir.file()) {
        StorageLocality::Local => LockingOutcome::Effective,
        StorageLocality::Remote => LockingOutcome::Weak(WeakLocking::SharedStorage),
        StorageLocality::Unknown => LockingOutcome::Weak(WeakLocking::UnknownStorage),
    }
}

/// A lock somebody else holds is the one case where the measurement is right to
/// stay silent: the second take would have been refused whatever the filesystem
/// does.
const CONTENDED_REASON: &str =
    "another lock on the directory was already held, so what a lock excludes could not be \
     established; run the check again once no other kapsaro command is running";

fn weak_locking_message(kind: WeakLocking) -> &'static str {
    match kind {
        WeakLocking::SharedStorage => "Directory locks cannot exclude another machine",
        WeakLocking::UnknownStorage => {
            "Directory locks were measured on storage of an unknown kind"
        }
        WeakLocking::Ineffective => "Directory locks exclude nobody",
        WeakLocking::Unsupported => "The filesystem does not support directory locks",
    }
}

/// What each finding means for the state the directory holds.
///
/// Every reason names the outcome rather than the mechanism, because a lost
/// change is what the operator has to weigh: a write that lands on top of
/// another leaves no trace of the one it replaced.
fn weak_locking_reason(kind: WeakLocking) -> &'static str {
    match kind {
        WeakLocking::SharedStorage => {
            "the directory is on storage served from another machine, where a lock holds only \
             between the processes on this host; two machines writing at the same time replace \
             each other's changes, and neither is told that anything was lost"
        }
        WeakLocking::UnknownStorage => {
            "a lock holds between the processes on this host, but this platform cannot tell \
             whether another machine reaches the same directory; if one does, two writes at the \
             same time replace each other's changes without either being told"
        }
        WeakLocking::Ineffective => {
            "a second lock on the directory was granted while the first was still held, so two \
             commands running at once do not see each other and the later write replaces the \
             earlier one without either being told"
        }
        WeakLocking::Unsupported => {
            "the filesystem refused the lock as an operation it does not implement, so two \
             commands running at once do not see each other and the later write replaces the \
             earlier one without either being told"
        }
    }
}

/// A lock cannot be repaired from here, so each action names the arrangement
/// that removes the exposure instead of a setting to change.
fn weak_locking_next_action(kind: WeakLocking) -> &'static str {
    match kind {
        WeakLocking::SharedStorage | WeakLocking::UnknownStorage => SINGLE_MACHINE_ACTION,
        WeakLocking::Ineffective | WeakLocking::Unsupported => SINGLE_COMMAND_ACTION,
    }
}

const SINGLE_MACHINE_ACTION: &str =
    "move the directory onto storage attached to this machine, or write it from one machine at \
     a time";

const SINGLE_COMMAND_ACTION: &str =
    "move the directory onto a filesystem that arbitrates locks, or run one kapsaro command at \
     a time";

#[cfg(test)]
#[path = "../../../../tests/unit/internal/app_doctor_local_state_locking_test.rs"]
mod tests;
