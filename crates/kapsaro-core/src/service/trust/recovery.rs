// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Service-layer recovery for invalid local trust stores.
//! Separates confirmation from identity-bound deletion of the document that failed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{
    LOCAL_STATE_PATH_UNSAFE_RECOVERY, TRUST_SIGNER_KEY_MISSING_RECOVERY,
    TRUST_STORE_RESET_REQUIRED_RECOVERY,
};
use crate::feature::trust::signer_keys::format_signer_key_recovery_route;
use crate::io::trust::paths::{get_trust_store_file_name, get_trust_store_file_path};
use crate::io::trust::remove::{
    format_failure_after_trust_store_removal, remove_confirmed_trust_store,
};
use crate::io::trust::store::{load_trust_store_at, validate_trust_directory};
use crate::model::identity::MemberHandle;
use crate::model::trust_store::TrustStoreProtected;
use crate::service::read::WorkspaceReadSession;
use crate::service::trust::list::TrustListCommand;
use crate::service::trust::TrustCommandSession;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock::with_exclusive_locked_directory;
use crate::support::fs::relative::{DirectoryFd, OpenDir};
use crate::support::fs::snapshot::{
    ensure_regular_file_matches_snapshot_at, load_optional_regular_file_snapshot_at,
    RegularFileSnapshot,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, ErrorKind, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustStoreResetCause {
    InvalidDocument,
    MissingSignerKey,
}

/// How many approvals a reset would discard.
///
/// Only a document that still parses can be counted. Content that will not
/// parse names no number, and a caller with nothing to report says nothing
/// rather than guessing at zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustStoreResetLoss {
    pub known_keys: usize,
    pub recipient_sets: usize,
}

/// What the local trust store was before the operation that may fail on it.
///
/// The failure and the reset offer are two separate reads of the same name, and
/// the document behind that name can be replaced in between. Observing it once
/// before the operation runs and binding the reset to that observation closes
/// the gap: the operator is never shown one document's failure and asked to
/// delete another.
///
/// Observing must not fail the operation it precedes, so an observation that
/// could not be taken travels as it is and only surfaces if a reset is offered.
#[derive(Debug)]
pub struct TrustStoreRecoveryToken {
    observed: Result<Option<RegularFileSnapshot>>,
}

/// The document a reset would delete, and what deleting it costs.
struct ResetTarget {
    snapshot: Option<RegularFileSnapshot>,
    loss: Option<TrustStoreResetLoss>,
}

#[derive(Debug)]
pub struct TrustStoreResetPlan {
    trust_dir: Option<Arc<OpenDir>>,
    target_snapshot: Option<RegularFileSnapshot>,
    owner_handle: MemberHandle,
    path: PathBuf,
    warning_message: String,
    cause: TrustStoreResetCause,
    loss: Option<TrustStoreResetLoss>,
}

#[derive(Debug)]
pub struct TrustStoreResetOutcome {
    pub path: PathBuf,
    /// Whether a stored document was actually removed.
    ///
    /// A reset can find nothing to delete: the trust directory may be absent,
    /// or the store may have been gone since the plan was built. Saying it was
    /// deleted anyway tells the operator a file was destroyed that never was.
    pub deleted: bool,
}

/// Classify an error as a condition that local trust store reset can recover.
///
/// The recovery route decides this on its own, without the kind being consulted
/// first. A recovery code and a validation rule are separate namespaces now, so
/// a code read here can only have been attached as a recovery route and never
/// arrives from an unrelated error that happens to be checked against a rule of
/// the same name. What the failure was stays readable from the kind, and a
/// reset is offered for it whether the bytes would not parse or the signature
/// over them did not verify.
pub fn evaluate_trust_store_reset(error: &Error) -> Option<TrustStoreResetCause> {
    match error.recovery() {
        Some(TRUST_STORE_RESET_REQUIRED_RECOVERY) => Some(TrustStoreResetCause::InvalidDocument),
        Some(TRUST_SIGNER_KEY_MISSING_RECOVERY) => Some(TrustStoreResetCause::MissingSignerKey),
        Some(_) | None => None,
    }
}

/// Observe the store a `trust list` run may later be asked to reset.
pub fn observe_trust_store_recovery_from_list_command(
    command: &TrustListCommand,
) -> TrustStoreRecoveryToken {
    let file_name = get_trust_store_file_name(command.owner());
    TrustStoreRecoveryToken {
        observed: observe_trust_store_document(command.trust_dir().map(Arc::as_ref), &file_name),
    }
}

/// Observe the store a command running under one execution may reset.
pub fn observe_trust_store_recovery_from_session(
    session: &TrustCommandSession,
) -> TrustStoreRecoveryToken {
    TrustStoreRecoveryToken {
        observed: observe_session_trust_store_document(session),
    }
}

fn observe_session_trust_store_document(
    session: &TrustCommandSession,
) -> Result<Option<RegularFileSnapshot>> {
    let file_name = get_trust_store_file_name(session.owner());
    let trust_dir = session.trust_dir().cloned();
    observe_trust_store_document(trust_dir.as_deref(), &file_name)
}

pub(crate) fn observe_trust_store_recovery_from_read_session(
    session: &WorkspaceReadSession<'_>,
) -> TrustStoreRecoveryToken {
    TrustStoreRecoveryToken {
        observed: observe_read_session_trust_store_document(session),
    }
}

fn observe_read_session_trust_store_document(
    session: &WorkspaceReadSession<'_>,
) -> Result<Option<RegularFileSnapshot>> {
    let file_name = get_trust_store_file_name(session.member_handle());
    let trust_dir = session.cloned_trust_directory()?;
    observe_trust_store_document(trust_dir.as_deref(), &file_name)
}

fn observe_trust_store_document(
    trust_dir: Option<&OpenDir>,
    file_name: &str,
) -> Result<Option<RegularFileSnapshot>> {
    let Some(trust_dir) = trust_dir else {
        return Ok(None);
    };
    validate_trust_directory(trust_dir)?;
    load_optional_regular_file_snapshot_at(trust_dir, file_name)
}

pub fn build_trust_store_reset_plan_from_list_command(
    command: &TrustListCommand,
    token: TrustStoreRecoveryToken,
    error: Error,
    confirmation_available: bool,
) -> Result<TrustStoreResetPlan> {
    let (error, cause) = build_reset_error(error, confirmation_available)?;
    build_resolved_reset_plan(
        command.owner().clone(),
        command.home(),
        command.trust_dir().cloned(),
        command.path().to_path_buf(),
        token,
        (error, cause),
    )
}

pub fn build_trust_store_reset_plan_from_session(
    session: &TrustCommandSession,
    token: TrustStoreRecoveryToken,
    error: Error,
    confirmation_available: bool,
) -> Result<TrustStoreResetPlan> {
    let (error, cause) = build_reset_error(error, confirmation_available)?;
    let home = session.home();
    let trust_dir = session.trust_dir().cloned();
    let path = get_trust_store_file_path(home.path(), session.owner());
    build_resolved_reset_plan(
        session.owner().clone(),
        Some(home),
        trust_dir,
        path,
        token,
        (error, cause),
    )
}

pub(crate) fn build_trust_store_reset_plan_from_read_session(
    session: &WorkspaceReadSession<'_>,
    token: TrustStoreRecoveryToken,
    error: Error,
    confirmation_available: bool,
) -> Result<TrustStoreResetPlan> {
    let (error, cause) = build_reset_error(error, confirmation_available)?;
    let home = session.local_state_home().ok_or_else(|| {
        Error::build_invalid_operation_error(
            "Command requires a fixed local-state home".to_string(),
        )
    })?;
    let trust_dir = session.cloned_trust_directory()?;
    let path = get_trust_store_file_path(home.path(), session.member_handle());
    build_resolved_reset_plan(
        session.member_handle().clone(),
        Some(home),
        trust_dir,
        path,
        token,
        (error, cause),
    )
}

fn build_resolved_reset_plan(
    owner_handle: MemberHandle,
    base: Option<&AnchoredDir>,
    trust_dir: Option<Arc<OpenDir>>,
    path: PathBuf,
    token: TrustStoreRecoveryToken,
    failure: (Error, TrustStoreResetCause),
) -> Result<TrustStoreResetPlan> {
    let file_name = get_trust_store_file_name(&owner_handle);
    let (error, cause) = failure;
    let target = resolve_reset_target(base, trust_dir.as_deref(), &file_name, token, &path)
        .map_err(|blocked| build_reset_target_failure_error(blocked, &error))?;
    Ok(TrustStoreResetPlan {
        path,
        trust_dir,
        target_snapshot: target.snapshot,
        owner_handle,
        warning_message: error.format_user_message().to_string(),
        cause,
        loss: target.loss,
    })
}

/// Bind the reset to the document the failing operation started from.
///
/// The observation was taken before that operation ran, so a document that
/// still matches it is the very one whose failure the operator is about to be
/// shown. Anything else is a concurrent change, reported as a conflict rather
/// than offered for deletion.
fn resolve_reset_target(
    base: Option<&AnchoredDir>,
    trust_dir: Option<&OpenDir>,
    file_name: &str,
    token: TrustStoreRecoveryToken,
    path: &Path,
) -> Result<ResetTarget> {
    let observed = token.observed?;
    let Some((base, trust_dir)) = base.zip(trust_dir) else {
        return Ok(ResetTarget {
            snapshot: None,
            loss: None,
        });
    };
    validate_trust_directory(trust_dir)?;
    let snapshot = ensure_regular_file_matches_snapshot_at(
        trust_dir,
        file_name,
        observed.as_ref(),
        &format_trust_store_name(path),
    )
    .map_err(|error| build_reset_conflict_error(error, path))?;
    Ok(ResetTarget {
        loss: count_stored_approvals(base, trust_dir, path),
        snapshot,
    })
}

/// Keep the failure that prompted the reset offer inside the one that replaced it.
///
/// The plan is the only thing that carries that failure to the operator, so a
/// plan that could not be built would otherwise leave them told to run the
/// command again with no word of what was wrong with the store.
fn build_reset_target_failure_error(blocked: Error, failure: &Error) -> Error {
    let message = format!(
        "{} The failure it would have reset the store for: {}",
        blocked.format_user_message(),
        failure.format_user_message()
    );
    if blocked.recovery() == Some(LOCAL_STATE_PATH_UNSAFE_RECOVERY) {
        return Error::build_local_state_path_unsafe_error(message);
    }
    if blocked.kind() == ErrorKind::Io {
        return Error::build_io_error(message);
    }
    Error::build_invalid_operation_error(message)
}

/// Report a failure met while binding the reset the way its cause allows.
///
/// A store that no longer matches the observation is the conflict this reports,
/// and it is named as one here because no confirmation has been shown yet. A
/// failure that never compared the two - an I/O fault, or a name that stopped
/// being a regular file - says nothing about which document stands there, so it
/// travels as itself instead of being reported as a document that moved.
fn build_reset_conflict_error(error: Error, path: &Path) -> Error {
    if error.kind() == ErrorKind::Io || error.recovery() == Some(LOCAL_STATE_PATH_UNSAFE_RECOVERY) {
        return error;
    }
    build_recovery_conflict_error(path)
}

/// Name one trust store the way every message about it names it.
fn format_trust_store_name(path: &Path) -> String {
    format!("Local trust store '{}'", format_path_relative_to_cwd(path))
}

/// Report a store that moved between the failure and the reset offer.
fn build_recovery_conflict_error(path: &Path) -> Error {
    Error::build_invalid_operation_error(format!(
        "Local trust store '{}' changed after the failure that would reset it, so the document to \
         delete is no longer the one that failed. Run the command again.",
        format_path_relative_to_cwd(path)
    ))
}

/// Count the approvals a deletion would discard, when the document still says.
///
/// A store whose signer key is merely missing holds intact approvals and can be
/// counted; one that will not load names no number, and the operator is told
/// nothing rather than a figure nothing stands behind.
/// The permission chain names the local state root as well as the trust
/// directory, so a read refused higher up is recorded the same way every other
/// read of the store records it.
fn count_stored_approvals<D>(
    base: &dyn DirectoryFd,
    locked_trust_dir: &D,
    path: &Path,
) -> Option<TrustStoreResetLoss>
where
    D: DirectoryFd,
{
    let permission_chain: [&dyn DirectoryFd; 2] = [base, locked_trust_dir];
    let loaded = load_trust_store_at(locked_trust_dir, path, &permission_chain).ok()??;
    Some(TrustStoreResetLoss::from(&loaded.document.protected))
}

impl From<&TrustStoreProtected> for TrustStoreResetLoss {
    fn from(protected: &TrustStoreProtected) -> Self {
        Self {
            known_keys: protected.known_keys.len(),
            recipient_sets: protected.recipient_sets.len(),
        }
    }
}

pub fn execute_trust_store_reset(plan: &TrustStoreResetPlan) -> Result<TrustStoreResetOutcome> {
    let mut deleted = false;
    if let Some(trust_dir) = plan.trust_dir.as_deref() {
        let file_name = get_trust_store_file_name(&plan.owner_handle);
        with_exclusive_locked_directory(trust_dir, |locked_trust_dir| {
            validate_trust_directory(locked_trust_dir)?;
            let confirmed = ensure_regular_file_matches_snapshot_at(
                locked_trust_dir,
                &file_name,
                plan.target_snapshot.as_ref(),
                &format_trust_store_name(&plan.path),
            )?;
            deleted =
                remove_confirmed_trust_store(locked_trust_dir, &file_name, confirmed, &plan.path)?;
            validate_trust_directory(locked_trust_dir)
                .map_err(|error| report_namespace_check_after_reset(&plan.path, deleted, error))
        })?;
    }
    Ok(TrustStoreResetOutcome {
        path: plan.path.clone(),
        deleted,
    })
}

/// Report the namespace check that runs once the deletion is done.
///
/// A run that deleted nothing has nothing to add and hands the failure on as it
/// is. The rule survives where there was one, because an unsafe local state is
/// the same finding whether or not a document was removed first.
fn report_namespace_check_after_reset(path: &Path, deleted: bool, error: Error) -> Error {
    if !deleted {
        return error;
    }
    let message = format_failure_after_trust_store_removal(
        path,
        "the trust directory could not be confirmed safe afterwards",
        &error,
    );
    if error.recovery() == Some(LOCAL_STATE_PATH_UNSAFE_RECOVERY) {
        return Error::build_local_state_path_unsafe_error(message);
    }
    Error::build_io_error(message)
}

impl TrustStoreResetPlan {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn warning_message(&self) -> &str {
        &self.warning_message
    }

    pub fn cause(&self) -> TrustStoreResetCause {
        self.cause
    }

    /// How many approvals the deletion would discard, when they can be counted.
    pub fn loss(&self) -> Option<TrustStoreResetLoss> {
        self.loss
    }

    /// The route that keeps the approvals, when the cause leaves one.
    ///
    /// A store whose signer key is unavailable holds approvals that are intact,
    /// so the way to keep them is restated immediately before the operator is
    /// asked to discard them. Content that will not verify has no such route.
    pub fn recovery_hint(&self) -> Option<String> {
        match self.cause {
            TrustStoreResetCause::MissingSignerKey => {
                Some(format_signer_key_recovery_route(&self.owner_handle))
            }
            TrustStoreResetCause::InvalidDocument => None,
        }
    }
}

fn build_confirmation_unavailable_error(error: Error) -> Error {
    Error::build_invalid_operation_error(format!(
        "{} (caller confirmation is required for trust store reset)",
        error.format_user_message()
    ))
}

fn require_reset_confirmation(error: Error, confirmation_available: bool) -> Result<Error> {
    if confirmation_available {
        Ok(error)
    } else {
        Err(build_confirmation_unavailable_error(error))
    }
}

fn build_reset_error(
    error: Error,
    confirmation_available: bool,
) -> Result<(Error, TrustStoreResetCause)> {
    let Some(cause) = evaluate_trust_store_reset(&error) else {
        return Err(error);
    };
    require_reset_confirmation(error, confirmation_available).map(|error| (error, cause))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_trust_recovery_test.rs"]
mod service_trust_recovery_test;
