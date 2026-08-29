// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store file I/O with atomic writes and permission enforcement.
//! Validates the complete trust namespace under a typed directory lock.

use crate::error::{LOCAL_STATE_PATH_UNSAFE_RECOVERY, TRUST_STORE_RESET_REQUIRED_RECOVERY};
use crate::format::schema::document::parse_trust_store_str;
use crate::io::document_store;
use crate::io::trust::paths::get_trust_store_owner_handle;
use crate::model::identity::MemberHandle;
use crate::model::trust_store::TrustStoreDocument;
use crate::support::fs::lock::{self, LockTargetDirectory};
use crate::support::fs::lock::{ExclusiveLockedDir, ReadLockedDirectory};
use crate::support::fs::permission::{collect_open_permission_violations, report_violations};
use crate::support::fs::relative::{
    is_write_staging_name, list_child_entries_at, write_staging_residue_error, ChildType,
    DirectoryFd,
};
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::{format_finding_path, format_path_relative_to_cwd};
use crate::support::post_write::{format_post_change_failure, CompletedChange};
use crate::{Error, Result};
use std::fmt;
use std::path::Path;

// Fault-injection seam: arms one trust store save to fail, which is how the
// tests reach the rollback path that a real I/O error would take.
#[cfg(test)]
thread_local! {
    static FAIL_NEXT_TRUST_STORE_SAVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Load result carrying the parsed document and the exact bytes it was parsed from.
pub struct TrustStoreLoadResult {
    pub document: TrustStoreDocument,
    pub(crate) raw_bytes: Vec<u8>,
}

/// Report the serialized bytes by length.
///
/// A trust store holds public keys and approval records, so this is about
/// keeping `{:?}` readable rather than hiding anything: the same content is
/// already rendered field by field through `document`.
impl fmt::Debug for TrustStoreLoadResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustStoreLoadResult")
            .field("document", &self.document)
            .field("raw_bytes", &format_args!("{} bytes", self.raw_bytes.len()))
            .finish()
    }
}

/// Presence and exact serialized bytes observed under a trust-directory read lock.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum TrustStoreSnapshot {
    Missing,
    Present(Vec<u8>),
}

/// Report the observed bytes by length.
///
/// The bytes identify one trust store content rather than describing it, and
/// that content is public, so `{:?}` states how much was observed instead of
/// replaying the whole store into every enclosing type's output.
impl fmt::Debug for TrustStoreSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("Missing"),
            Self::Present(bytes) => write!(f, "Present({} bytes)", bytes.len()),
        }
    }
}

impl TrustStoreSnapshot {
    pub(crate) fn from_loaded(loaded: Option<&TrustStoreLoadResult>) -> Self {
        loaded.map_or(Self::Missing, |loaded| {
            Self::Present(loaded.raw_bytes.clone())
        })
    }
}

pub(crate) fn load_trust_store_with_shared_lock<D>(
    base: &dyn DirectoryFd,
    trust_dir: &D,
    path: &Path,
) -> Result<Option<TrustStoreLoadResult>>
where
    D: DirectoryFd + LockTargetDirectory,
{
    lock::with_shared_locked_directory(trust_dir, |locked_trust_dir| {
        let permission_chain: [&dyn DirectoryFd; 2] = [base, locked_trust_dir];
        load_trust_store_at(locked_trust_dir, path, &permission_chain)
    })
}

pub(crate) fn load_trust_store_at<D>(
    dir: &D,
    path: &Path,
    permission_chain: &[&dyn DirectoryFd],
) -> Result<Option<TrustStoreLoadResult>>
where
    D: ReadLockedDirectory,
{
    validate_trust_directory(dir)?;
    let Some(loaded) = document_store::load_optional_with_raw_at(
        dir,
        path,
        permission_chain,
        MAX_JSON_DOCUMENT_READ_SIZE,
        "Trust store",
        |content| parse_trust_store(content, path),
    )?
    else {
        return Ok(None);
    };
    let document = loaded.document;
    validate_filename_matches_owner(path, &document)?;

    Ok(Some(TrustStoreLoadResult {
        document,
        raw_bytes: raw_content_bytes(loaded.raw_content)?,
    }))
}

/// Take the trust directory's exclusive lock and read what is stored under it.
///
/// The load outcome is handed over unmapped: only the caller knows whether a
/// content failure here means the store moved out from under a review or is a
/// store to report as it is.
pub(crate) fn with_exclusive_trust_store_load<D, T, F>(
    base: &dyn DirectoryFd,
    dir: &D,
    path: &Path,
    commit: F,
) -> Result<T>
where
    D: DirectoryFd + LockTargetDirectory,
    F: FnOnce(&ExclusiveLockedDir<'_>, Result<Option<TrustStoreLoadResult>>) -> Result<T>,
{
    lock::with_exclusive_locked_directory(dir, |locked_dir| {
        let permission_chain: [&dyn DirectoryFd; 2] = [base, locked_dir];
        let loaded = load_trust_store_at(locked_dir, path, &permission_chain);
        commit(locked_dir, loaded)
    })
}

/// Report content that is no longer the content the caller acted on.
///
/// The wording names the read rather than a review, because the writers that
/// merge into the latest state reach this too and have shown the operator
/// nothing. The operator is told to run the command again rather than being
/// offered a reset: the stored approvals are intact as far as this write knows,
/// and only a fresh read can say what they now hold.
pub(crate) fn build_trust_store_conflict_error() -> Error {
    Error::build_invalid_operation_error(
        "Local trust store changed since this command read it. Run the command again.".to_string(),
    )
}

pub(crate) fn validate_trust_directory<D>(dir: &D) -> Result<()>
where
    D: DirectoryFd,
{
    for (name, child_type) in list_child_entries_at(dir)? {
        if is_write_staging_name(&name) {
            return Err(write_staging_residue_error(dir, &name));
        }
        if is_safe_trust_directory_entry(&name, child_type) {
            continue;
        }
        return Err(Error::build_local_state_path_unsafe_error(format!(
            "Unexpected {:?} entry in local trust directory: {}",
            child_type,
            format_finding_path(&dir.path().join(name))
        )));
    }
    Ok(())
}

/// Regular files are always fine: unrecognised ones are OS or tool metadata and
/// trust store files are the point of the directory. A directory or a symlink
/// taking a trust store's own name would shadow it; under any other name it is
/// an entry the loader never reads.
fn is_safe_trust_directory_entry(name: &str, child_type: ChildType) -> bool {
    match child_type {
        ChildType::RegularFile => true,
        ChildType::Directory | ChildType::Symlink => !is_canonical_trust_store_name(name),
        ChildType::Other => false,
    }
}

fn is_canonical_trust_store_name(name: &str) -> bool {
    get_trust_store_owner_handle(name).is_some_and(|owner| MemberHandle::try_from(owner).is_ok())
}

/// Save a trust store and re-check the directory it landed in.
///
/// The directory the approvals land in is inspected before the write, matching
/// what the read path inspects before it hands a store back. The permissions
/// are read over the same chain that path reports, the local state root as well
/// as the trust directory, so a write is not told less than a read. The write
/// goes ahead either way, so the operator gets the approval they asked for and
/// is told that the directory holding it is open to others.
pub(crate) fn save_trust_store_at(
    base: &dyn DirectoryFd,
    dir: &ExclusiveLockedDir<'_>,
    path: &Path,
    document: &TrustStoreDocument,
) -> Result<()> {
    validate_trust_directory(dir)?;
    let permission_chain: [&dyn DirectoryFd; 2] = [base, dir];
    report_violations(collect_open_permission_violations(&permission_chain));
    enforce_test_save_allowed()?;
    document_store::save_json_restricted_at(dir, document_store::file_name(path)?, document)?;
    run_post_trust_store_save_hook();
    validate_trust_directory(dir).map_err(|error| build_post_save_validation_error(error, path))
}

// Test-only seam: runs once the document is on disk but before the re-check, so
// a test can introduce a concurrent change there. Compiled out of production.
#[cfg(test)]
thread_local! {
    static POST_TRUST_STORE_SAVE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_post_trust_store_save_hook() {
    POST_TRUST_STORE_SAVE_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_post_trust_store_save_hook() {}

#[cfg(test)]
pub(crate) fn set_post_trust_store_save_hook(hook: impl FnOnce() + 'static) {
    POST_TRUST_STORE_SAVE_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

/// Report the outcome of the re-check that follows a trust store save. The
/// document is already on disk, so every message here says so rather than
/// reading as a failed write.
///
/// Only a genuine unsafe-entry detection is folded into
/// `E_LOCAL_STATE_PATH_UNSAFE`: `validate_trust_directory` reports one with
/// that rule. A plain I/O failure during the re-check (`EIO`, a permission
/// error, ...) keeps its own `ErrorKind::Io` instead, so the caller can still
/// tell a corrupted directory from a transient read failure and does not lose
/// the diagnostic the original error carried.
fn build_post_save_validation_error(error: Error, path: &Path) -> Error {
    let detail = error.format_user_message().to_string();
    if error.recovery() == Some(LOCAL_STATE_PATH_UNSAFE_RECOVERY) {
        return Error::build_local_state_path_unsafe_error(format_post_change_failure(
            "Trust store",
            path,
            CompletedChange::Written,
            "the local trust directory became unsafe immediately after",
            &detail,
        ));
    }
    Error::build_io_error(format_post_change_failure(
        "Trust store",
        path,
        CompletedChange::Written,
        "the post-save re-check of the local trust directory failed",
        &detail,
    ))
}

#[cfg(test)]
pub(crate) fn fail_next_trust_store_save() {
    FAIL_NEXT_TRUST_STORE_SAVE.with(|fail| fail.set(true));
}

#[cfg(test)]
fn enforce_test_save_allowed() -> Result<()> {
    let should_fail = FAIL_NEXT_TRUST_STORE_SAVE.with(|fail| fail.replace(false));
    if should_fail {
        return Err(Error::build_io_error("Injected trust store save failure"));
    }
    Ok(())
}

#[cfg(not(test))]
fn enforce_test_save_allowed() -> Result<()> {
    Ok(())
}

/// The trust store loader always retains its source text, so an absent value
/// means the loader was wired to the wrong entry point.
fn raw_content_bytes(raw_content: Option<String>) -> Result<Vec<u8>> {
    raw_content.map(String::into_bytes).ok_or_else(|| {
        Error::build_io_error(
            "Trust store was loaded without retaining its serialized bytes".to_string(),
        )
    })
}

fn parse_trust_store(content: &str, path: &Path) -> Result<TrustStoreDocument> {
    parse_trust_store_str(content, &format_path_relative_to_cwd(path))
}

/// Validate that file name stem matches protected.owner_handle.
fn validate_filename_matches_owner(path: &Path, document: &TrustStoreDocument) -> Result<()> {
    let stem = file_stem(path)?;

    if stem != document.protected.owner_handle {
        return Err(Error::build_verification_error(
            "E_TRUST_STORE_FILENAME_MISMATCH".to_string(),
            format!(
                "File name stem '{}' does not match owner_handle '{}'",
                stem, document.protected.owner_handle
            ),
        ));
    }
    Ok(())
}

/// The stem a trust store file is named by.
///
/// A path with no stem, or one whose stem is not UTF-8, is never a trust store
/// file. Naming that as its own failure keeps it apart from a stem that was
/// read and did not match the owner handle.
fn file_stem(path: &Path) -> Result<&str> {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| {
            Error::build_config_error(format!(
                "Invalid trust store path '{}'",
                format_finding_path(path)
            ))
        })
}

/// Name deleting the store as the route out of a failure the store itself caused.
///
/// Parsing, schema validation, and signature verification all read the stored
/// bytes, so a failure of theirs proves the document unusable and a reset is
/// what gets past it. The cause is left exactly as it was: a caller that wants
/// to log a schema mismatch differently from a forged signature still reads
/// that from the kind, and the recovery route rides alongside it.
///
/// A failure that never reached the document is untouched. An I/O fault or a
/// refused permission says nothing about the content, so neither is answered
/// with an offer to discard approvals a retry or a `chmod` would give back.
///
/// A failure that already names a repair is untouched for the same reason, and
/// is left describing whatever it was actually about. A missing signer key is
/// repaired by restoring that one key, which offering to delete intact
/// approvals would talk over; an unsafe path can be the keystore's rather than
/// the store's, and naming the store for it would send the operator to a file
/// that is not what is wrong.
pub(crate) fn attach_trust_store_recovery(path: &Path, error: Error) -> Error {
    if error.recovery().is_some() || !error.kind().is_content_failure() {
        return error;
    }
    let message = format!(
        "Local trust store '{}' is invalid and must be reset: {}",
        format_path_relative_to_cwd(path),
        error.format_user_message()
    );
    error
        .with_message(message)
        .with_recovery(TRUST_STORE_RESET_REQUIRED_RECOVERY)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_trust_store_test.rs"]
mod io_trust_store_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_trust_store_recovery_test.rs"]
mod io_trust_store_recovery_test;
