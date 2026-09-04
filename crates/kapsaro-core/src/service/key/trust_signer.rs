// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Guard protecting the local trust store signature from a key removal.
//! Decides whether a removal may proceed, has to re-sign first, or must be refused.

use crate::error::TRUST_SIGNER_KEY_IN_USE_RECOVERY;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::paths::get_public_key_file_path_from_root;
use crate::model::identity::{Kid, MemberHandle};
use crate::service::key::manage::KeyCommandCapabilities;
use crate::service::trust::store::{
    plan_trust_store_resign_bound_session, TrustSignerRecord, TrustStoreResignPlan,
};
use crate::service::trust::TrustCommandSession;
use crate::support::path::format_finding_path;
use crate::{Error, Result};

/// The one key removal this guard is deciding about.
pub(super) struct TrustSignerRemovalRequest<'a> {
    pub(super) member_handle: &'a MemberHandle,
    pub(super) kid: &'a Kid,
    pub(super) force: bool,
}

/// What removing one key would do to the stored trust store signature.
pub(super) enum TrustSignerRemoval {
    /// The key does not carry the stored signature.
    Unrelated,
    /// Another key can carry the signature, so it is handed over first.
    ResignFirst,
    /// Nothing else can sign, so the stored approvals would stop verifying.
    LastSigner,
    /// The stored content cannot be read, so the key cannot be ruled out.
    UnknownSigner(Error),
}

impl TrustSignerRemoval {
    /// Whether acting on this classification writes to the local trust store.
    ///
    /// Only the hand-over does, and it is the one step whose effect outlives a
    /// removal that is refused afterwards.
    pub(super) fn writes_to_trust_store(&self) -> bool {
        matches!(self, Self::ResignFirst)
    }
}

/// What the guard did, and what the operator has to be told about it.
pub(super) struct TrustSignerRemovalOutcome {
    pub(super) resigned_trust_store_kid: Option<String>,
    pub(super) trust_store_warning: Option<String>,
}

impl TrustSignerRemovalOutcome {
    fn untouched() -> Self {
        Self {
            resigned_trust_store_kid: None,
            trust_store_warning: None,
        }
    }

    fn resigned(signer_kid: String) -> Self {
        Self {
            resigned_trust_store_kid: Some(signer_kid),
            trust_store_warning: None,
        }
    }

    fn warned(warning: String) -> Self {
        Self {
            resigned_trust_store_kid: None,
            trust_store_warning: Some(warning),
        }
    }
}

/// Classify a removal against the signature the stored trust store carries.
///
/// The stored signer is read and released before the keystore is consulted, so
/// this never holds the trust lock and the member lock at the same time.
pub(super) fn resolve_trust_signer_removal(
    capabilities: &KeyCommandCapabilities,
    request: &TrustSignerRemovalRequest<'_>,
) -> Result<TrustSignerRemoval> {
    match capabilities.stored_trust_signer(request.member_handle) {
        TrustSignerRecord::Absent => Ok(TrustSignerRemoval::Unrelated),
        TrustSignerRecord::Unreadable(error) => Ok(TrustSignerRemoval::UnknownSigner(error)),
        TrustSignerRecord::Signer(signer_kid) if signer_kid != request.kid.as_str() => {
            Ok(TrustSignerRemoval::Unrelated)
        }
        TrustSignerRecord::Signer(_) => evaluate_signer_removal(capabilities.keystore(), request),
    }
}

/// Decide whether another key of the same member can take the signature over.
fn evaluate_signer_removal(
    access: &KeystoreAccess,
    request: &TrustSignerRemovalRequest<'_>,
) -> Result<TrustSignerRemoval> {
    match access.load_active_kid(request.member_handle)? {
        Some(active) if active != *request.kid => Ok(TrustSignerRemoval::ResignFirst),
        _ => Ok(TrustSignerRemoval::LastSigner),
    }
}

/// Act on the classification before the key is removed.
///
/// The hand-over is always attempted, because handing the signature to a key
/// that stays costs the operator nothing and keeps the approvals. What `force`
/// covers is the case where it cannot happen at all: no other key to sign with,
/// a hand-over that failed, or a stored document that cannot be read well enough
/// to say which key signed it. All three are the operator's call to accept, and
/// what each of them costs the stored approvals is what the report says.
pub(super) fn apply_trust_signer_removal<Resign>(
    capabilities: &KeyCommandCapabilities,
    removal: TrustSignerRemoval,
    request: &TrustSignerRemovalRequest<'_>,
    resolve_signing_execution: Resign,
) -> Result<TrustSignerRemovalOutcome>
where
    Resign: FnOnce(&MemberHandle) -> Result<TrustCommandSession>,
{
    let access = capabilities.keystore();
    match removal {
        TrustSignerRemoval::Unrelated => Ok(TrustSignerRemovalOutcome::untouched()),
        TrustSignerRemoval::ResignFirst => {
            hand_signature_over(capabilities, request, resolve_signing_execution)
        }
        TrustSignerRemoval::UnknownSigner(error) if !request.force => Err(
            build_unreadable_store_error(request.member_handle, request.kid, error),
        ),
        TrustSignerRemoval::UnknownSigner(error) => Ok(TrustSignerRemovalOutcome::warned(
            build_unreadable_store_warning(access, request, &error),
        )),
        TrustSignerRemoval::LastSigner if request.force => Ok(TrustSignerRemovalOutcome::warned(
            build_last_signer_warning(access, request),
        )),
        TrustSignerRemoval::LastSigner => Err(build_signer_key_in_use_error(request)),
    }
}

/// What the stored signature turned out to be when a hand-over stopped.
///
/// The three cases cost the stored approvals different things, so they are told
/// apart here rather than reported as one failed hand-over: a signature the
/// hand-over refused to lift off the removed key goes away with it, one already
/// moved to another key stays verifiable, and one the hand-over never settled
/// rules nothing out either way.
enum HandoverFailure {
    /// The hand-over was refused because it would leave the signature in place.
    StillSigner(Error),
    /// The signature had already moved to another key of this member.
    AlreadyMoved(Kid),
    /// The hand-over stopped without settling which key the signature names.
    Unobserved(Error),
}

/// Move the stored signature onto another key before this one disappears.
///
/// A hand-over that cannot run is restated as a decision this command can make:
/// the operator is told the removal was stopped and what would let it go on.
fn hand_signature_over<Resign>(
    capabilities: &KeyCommandCapabilities,
    request: &TrustSignerRemovalRequest<'_>,
    resolve_signing_execution: Resign,
) -> Result<TrustSignerRemovalOutcome>
where
    Resign: FnOnce(&MemberHandle) -> Result<TrustCommandSession>,
{
    let access = capabilities.keystore();
    match attempt_signature_handover(capabilities, request, resolve_signing_execution) {
        Ok(signer_kid) => Ok(TrustSignerRemovalOutcome::resigned(signer_kid)),
        Err(failure) if request.force => Ok(TrustSignerRemovalOutcome::warned(
            format_failed_handover(access, request, &failure),
        )),
        Err(failure) => Err(build_stopped_handover_error(request, failure)),
    }
}

/// Re-sign the stored trust store and report the key that now carries it.
///
/// The caller only supplies the signing identity, which is what needs an SSH
/// key and an operator at the terminal. Resolving it walks the configured path
/// again, so what comes back is checked twice before anything is signed: the
/// member this removal is about, and the very local state directories this
/// command opened. The first keeps the hand-over inside that member's own
/// store, the second keeps it inside the store the removal was decided against.
///
/// The write is planned before it is taken, so the conditions that would refuse
/// it are met while the stored signature is still untouched. A refusal after
/// the write would leave the signature moved for a key the command then keeps.
fn attempt_signature_handover<Resign>(
    capabilities: &KeyCommandCapabilities,
    request: &TrustSignerRemovalRequest<'_>,
    resolve_signing_execution: Resign,
) -> std::result::Result<String, HandoverFailure>
where
    Resign: FnOnce(&MemberHandle) -> Result<TrustCommandSession>,
{
    let session =
        resolve_signing_execution(request.member_handle).map_err(HandoverFailure::Unobserved)?;
    if session.owner() != request.member_handle {
        let error = build_foreign_signing_identity_error(request.member_handle, session.owner());
        return Err(HandoverFailure::Unobserved(error));
    }
    let planned =
        plan_trust_store_resign_bound_session(&session, &capabilities.local_state_binding())
            .map_err(HandoverFailure::Unobserved)?;
    if let Some(failure) = find_failed_handover(&planned, request) {
        return Err(failure);
    }
    // A commit that does not come back settles nothing about the stored
    // signature: the write may have landed and been reported as failed
    // afterwards, and another writer taking the exclusive lock first is what
    // the conflict itself reports. The removed key carried the signature when
    // the plan observed it, and that is the last thing this knows.
    planned
        .commit()
        .map(|outcome| outcome.signer_kid)
        .map_err(HandoverFailure::Unobserved)
}

fn build_foreign_signing_identity_error(expected: &MemberHandle, resolved: &MemberHandle) -> Error {
    Error::build_invalid_operation_error(format!(
        "Handing the local trust store signature over for member '{}' resolved a signing identity \
         for '{}'.",
        expected, resolved
    ))
}

/// Refuse a hand-over that would not take the signature off the removed key.
///
/// A signature that has moved to another key on its own and one that would name
/// the removed key again are both refused, but they are not the same finding: a
/// signature lifted off the removed key is carried by a key that stays, while
/// one written back onto the removed key goes away with it. A signature the
/// removed key does carry, handed to a key that stays, is the one case that
/// moves it, so nothing else needs asking: the write that follows is a
/// re-signing by construction.
fn find_failed_handover(
    planned: &TrustStoreResignPlan<'_>,
    request: &TrustSignerRemovalRequest<'_>,
) -> Option<HandoverFailure> {
    let kid = request.kid;
    let previous_signer_kid = planned.previous_signer_kid();
    if previous_signer_kid != kid {
        return Some(HandoverFailure::AlreadyMoved(previous_signer_kid.clone()));
    }
    if planned.next_signer_kid() == kid.as_str() {
        return Some(HandoverFailure::StillSigner(
            build_signature_would_stay_error(kid),
        ));
    }
    None
}

fn build_signature_would_stay_error(kid: &Kid) -> Error {
    Error::build_invalid_operation_error(format!(
        "Handing the local trust store signature away from key '{}' cannot complete: the new \
         signature would name that key again.",
        kid
    ))
}

/// Refuse the removal the hand-over stopped, the way that hand-over ended.
fn build_stopped_handover_error(
    request: &TrustSignerRemovalRequest<'_>,
    failure: HandoverFailure,
) -> Error {
    match failure {
        HandoverFailure::AlreadyMoved(signer_kid) => {
            build_moved_signature_error(request, &signer_kid)
        }
        HandoverFailure::StillSigner(cause) | HandoverFailure::Unobserved(cause) => {
            build_failed_handover_error(request, cause)
        }
    }
}

/// Report the removal the hand-over stopped, the way that hand-over ended.
fn format_failed_handover(
    access: &KeystoreAccess,
    request: &TrustSignerRemovalRequest<'_>,
    failure: &HandoverFailure,
) -> String {
    match failure {
        HandoverFailure::AlreadyMoved(signer_kid) => {
            build_moved_signature_warning(request, signer_kid)
        }
        HandoverFailure::StillSigner(cause) => {
            build_failed_handover_warning(access, request, cause)
        }
        HandoverFailure::Unobserved(cause) => {
            build_unobserved_handover_warning(access, request, cause)
        }
    }
}

/// Refuse a removal whose signature another writer had already moved.
///
/// The stored signature names a key this member still holds, so the approvals
/// keep verifying and there is nothing to accept: the removal is a different
/// one from the one that was classified, and re-running it settles that.
fn build_moved_signature_error(request: &TrustSignerRemovalRequest<'_>, signer_kid: &Kid) -> Error {
    Error::build_invalid_operation_error(format!(
        "Handing the local trust store signature away from key '{}' cannot complete: the stored \
         signature now names key '{}', which this member still holds, so the stored approvals \
         verify without '{}'. Run 'kapsaro key remove {} --member-handle {}' again to remove it.",
        request.kid, signer_kid, request.kid, request.kid, request.member_handle
    ))
}

fn build_signer_key_in_use_error(request: &TrustSignerRemovalRequest<'_>) -> Error {
    Error::build_invalid_operation_error(format!(
        "Key '{}' signs the local trust store and no other key can take the signature over. Run \
         'kapsaro key activate <other-kid> --member-handle {}' first, or pass --force to remove it \
         and lose the stored approvals.",
        request.kid, request.member_handle
    ))
    .with_recovery(TRUST_SIGNER_KEY_IN_USE_RECOVERY)
}

/// Refuse a removal whose hand-over could not run, naming what would let it.
///
/// A cause that already names a recovery route names the repair it needs, and
/// the local recovery a broken trust store offers is chosen from that route, so
/// such a cause travels on as it is. What is restated here is the failure
/// naming no route of its own, where the operator would otherwise meet a bare
/// signing error with nothing said about the removal it stopped.
///
/// The cause is what gets repaired, and it is not always repairable in place:
/// an absent ssh-agent or an expired key is fixed and the removal re-run, while
/// a member whose only other key cannot sign at all is answered by activating
/// one that can. Both routes are named, and `--force` is stated as what it
/// costs rather than as the way out.
fn build_failed_handover_error(request: &TrustSignerRemovalRequest<'_>, cause: Error) -> Error {
    if cause.recovery().is_some() {
        return cause;
    }
    Error::build_invalid_operation_error(format!(
        "Key '{}' signed the local trust store when this removal was decided, and handing the \
         signature to the active key failed: {}. The key was not removed. Repair that and run the \
         removal again, or run 'kapsaro key activate <other-kid> --member-handle {}' to make a key \
         that can sign active. Passing --force removes the key without the hand-over and gives up \
         the stored approvals.",
        request.kid,
        cause.format_user_message(),
        request.member_handle
    ))
    .with_recovery(TRUST_SIGNER_KEY_IN_USE_RECOVERY)
}

fn build_last_signer_warning(
    access: &KeystoreAccess,
    request: &TrustSignerRemovalRequest<'_>,
) -> String {
    format!(
        "Removed key '{}' signed the local trust store, and no other key could take the \
         signature over. {}",
        request.kid,
        format_signature_recovery(access, request)
    )
}

/// Report a removal that went ahead after the signature could not be moved.
///
/// The reason is carried through because it decides what the operator does
/// next: an absent ssh-agent or an expired key is repaired and the store
/// re-signed, while a store that no longer verifies is not.
fn build_failed_handover_warning(
    access: &KeystoreAccess,
    request: &TrustSignerRemovalRequest<'_>,
    error: &Error,
) -> String {
    format!(
        "Removed key '{}' signed the local trust store, and handing the signature to the active \
         key failed: {}. {}",
        request.kid,
        error.format_user_message(),
        format_signature_recovery(access, request)
    )
}

/// Report a removal that went ahead once the signature had moved on its own.
///
/// Another writer put the signature on a key this member still holds, so the
/// stored approvals verify as they are and nothing has to be restored. Saying
/// they no longer verify would send the operator to reset a store that is
/// intact, so what the report names is the key now carrying it.
fn build_moved_signature_warning(
    request: &TrustSignerRemovalRequest<'_>,
    signer_kid: &Kid,
) -> String {
    format!(
        "Removed key '{}' no longer signed the local trust store: the stored signature had been \
         handed to key '{}' before this removal reached it, so the signature was left where it \
         was. The stored approvals still verify under '{}'.",
        request.kid, signer_kid, signer_kid
    )
}

/// Report a removal that went ahead on a hand-over that settled nothing.
///
/// The removed key carried the signature when the hand-over was planned, and
/// the hand-over stopped without establishing where the signature stands now:
/// the write may have landed, and another writer may have taken the signature
/// somewhere else. Claiming the removed key still signs would send the operator
/// to restore a key for a store that may well be intact, so what is reported is
/// that it was not established.
fn build_unobserved_handover_warning(
    access: &KeystoreAccess,
    request: &TrustSignerRemovalRequest<'_>,
    error: &Error,
) -> String {
    format!(
        "Removed key '{}' signed the local trust store when this removal was decided, and handing \
         the signature to the active key stopped without settling which key the stored signature \
         names now: {}. {}",
        request.kid,
        error.format_user_message(),
        format_unconfirmed_signature_recovery(access, request)
    )
}

/// Refuse a removal decided against a trust store nothing could read.
///
/// A cause that already names a recovery route names the repair it needs, and
/// the local recovery a broken store offers is chosen from that route, so such
/// a cause travels on as it is. What is restated here is the failure naming no
/// route of its own, where the operator would otherwise meet a bare read error
/// with nothing said about the removal it stopped.
fn build_unreadable_store_error(member_handle: &MemberHandle, kid: &Kid, cause: Error) -> Error {
    if cause.recovery().is_some() {
        return cause;
    }
    Error::build_invalid_operation_error(format!(
        "The local trust store could not be read, so key '{}' cannot be ruled out as the key that \
         signed it: {}. The key was not removed. Repair the store and run 'kapsaro key remove {} \
         --member-handle {}' again, or pass --force to remove the key and accept that the stored \
         approvals stop verifying.",
        kid,
        cause.format_user_message(),
        kid,
        member_handle
    ))
    .with_recovery(TRUST_SIGNER_KEY_IN_USE_RECOVERY)
}

/// Report a removal forced past a trust store nothing could read.
///
/// Content that does not load names no signer and rules none out, so the
/// removed key may well be the one the approvals hang on. The operator is told
/// the document is unverifiable and what taking the key back would require.
fn build_unreadable_store_warning(
    access: &KeystoreAccess,
    request: &TrustSignerRemovalRequest<'_>,
    error: &Error,
) -> String {
    format!(
        "The local trust store could not be read, so removed key '{}' cannot be ruled out as the \
         key that signed it: {}. {}",
        request.kid,
        error.format_user_message(),
        format_signature_recovery(access, request)
    )
}

/// The one way back to a verifying store once its signer key is gone.
///
/// The public half is what lets the stored signature be verified once more, and
/// `kapsaro trust resign` is what moves that signature onto the key this member
/// has active. Both steps are named because either one alone leaves the
/// approvals where they are: unverifiable.
fn format_signature_restoration(
    access: &KeystoreAccess,
    request: &TrustSignerRemovalRequest<'_>,
) -> String {
    let public_key_path =
        get_public_key_file_path_from_root(access.root(), request.member_handle, request.kid);
    format!(
        "restore the complete original public.json from a trusted backup or known-good copy to \
         '{}' with owner-only permissions and run 'kapsaro trust resign --member-handle {}', \
         which hands the signature to the key this member has active. If no trusted copy exists, \
         reset the trust store and review the approvals again.",
        format_finding_path(&public_key_path),
        request.member_handle
    )
}

fn format_signature_recovery(
    access: &KeystoreAccess,
    request: &TrustSignerRemovalRequest<'_>,
) -> String {
    format!(
        "The stored approvals no longer verify. To keep them, {}",
        format_signature_restoration(access, request)
    )
}

/// The way back when it was not even settled that anything was lost.
///
/// The hand-over may have landed, and another writer may have moved the
/// signature to a key this member still holds, so the store is as likely intact
/// as it is unverifiable. Re-signing settles it either way: it repairs a store
/// whose signature can still be verified, and reports one whose signature
/// cannot.
fn format_unconfirmed_signature_recovery(
    access: &KeystoreAccess,
    request: &TrustSignerRemovalRequest<'_>,
) -> String {
    format!(
        "Whether the stored approvals still verify was not established. Run 'kapsaro trust \
         resign --member-handle {}' to settle it: if that reports the stored trust store cannot \
         be verified, {}",
        request.member_handle,
        format_signature_restoration(access, request)
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_key_trust_signer_test.rs"]
mod service_key_trust_signer_test;
