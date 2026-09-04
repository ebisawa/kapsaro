// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store load and mutation entry points bound to fixed filesystem capabilities.
//! Resolves the capabilities one mutation writes through and hands them to the core.

use crate::feature::context::crypto::{build_signing_context, VerifiedSigningContext};
use crate::feature::trust::store_mutation::{
    build_empty_trust_store, build_trust_store_not_found_error, TrustStoreMutation,
    TrustStoreState, TrustStoreWrite,
};
use crate::io::keystore::access::KeystoreAccess;
use crate::io::trust::store::attach_trust_store_recovery;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::TrustStoreProtected;
use crate::service::trust::persistence::{TrustStoreMutationMode, TrustStoreMutationTarget};
use crate::service::trust::transaction::{
    commit_trust_store_mutation, ObservedTrustStore, TrustStoreCommitGate, TrustStorePreparation,
};
use crate::service::trust::{
    LocalTrustStore, TrustCommandSession, VerifiedLocalTrustStoreLoadResult,
};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_dir_identity, DirectoryFd, OpenDir};
use crate::{Error, Result};
use std::path::PathBuf;
use std::sync::Arc;

/// Capabilities one CLI trust store mutation resolved before taking any lock.
struct TrustMutationResolution<'a> {
    base: AnchoredDir,
    trust_dir: Arc<OpenDir>,
    path: PathBuf,
    keystore: &'a KeystoreAccess,
    owner: MemberHandle,
    mode: TrustStoreMutationMode,
}

impl TrustMutationResolution<'_> {
    /// Bind the resolved capabilities to the key that signs this mutation.
    fn target<'a>(
        &'a self,
        signing: &'a VerifiedSigningContext<'a>,
    ) -> TrustStoreMutationTarget<'a> {
        TrustStoreMutationTarget {
            base: &self.base,
            trust_dir: self.trust_dir.as_ref(),
            path: &self.path,
            owner: &self.owner,
            mode: self.mode,
            signing,
        }
    }

    /// Observe the canonical stored bytes and the signer key before commit.
    ///
    /// A failure here happened before any gate was consulted, so it says what
    /// it is: the cause survives, carrying the route back with it, instead of
    /// becoming a claim that the content moved. Only a gate bound to reviewed
    /// content makes that claim, and it makes it about a store that will not
    /// read back too, because the operator was shown something and this is no
    /// longer it. A merged write showed nobody anything and reports such a
    /// store the same way this observation does.
    fn observe(&self) -> Result<ObservedTrustStore> {
        ObservedTrustStore::observe(
            &self.base,
            self.trust_dir.as_ref(),
            &self.path,
            &self.owner,
            self.keystore,
        )
        .map_err(|error| attach_trust_store_recovery(&self.path, error))
    }
}

pub(crate) fn load_session_trust_store(
    session: &TrustCommandSession,
) -> Result<Option<TrustStoreState>> {
    load_session_verified_trust_store(session)
        .map(|loaded| loaded.map(VerifiedLocalTrustStoreLoadResult::into_state))
}

pub(crate) fn load_session_verified_trust_store(
    session: &TrustCommandSession,
) -> Result<Option<VerifiedLocalTrustStoreLoadResult>> {
    load_verified_local_trust_store(
        session.home(),
        session.trust_dir().map(Arc::as_ref),
        session.owner().clone(),
        Some(session.keystore()),
    )
}

/// Load and verify one trust store through its fixed local-state capability.
/// Returns `None` when the trust directory or the store file is absent.
///
/// The canonical document is read as an atomically published snapshot before
/// the keystore is consulted.
pub(crate) fn load_optional_trust_store(
    base: &AnchoredDir,
    trust_dir: Option<&OpenDir>,
    owner: &MemberHandle,
    keystore: Option<&KeystoreAccess>,
) -> Result<Option<TrustStoreState>> {
    load_verified_local_trust_store(base, trust_dir, owner.clone(), keystore)
        .map(|loaded| loaded.map(VerifiedLocalTrustStoreLoadResult::into_state))
}

pub(crate) fn trust_store_or_empty(
    owner: &MemberHandle,
    loaded: Option<TrustStoreState>,
) -> Result<TrustStoreState> {
    loaded.map_or_else(|| build_empty_trust_store(owner), Ok)
}

/// Load and verify the local trust store through the public API facade.
///
/// The facade verifies the store and reports a failure of the stored document as
/// a condition of that store, so every read of a trust store ends up
/// saying the same thing about the same file whichever entry point it came in by.
///
/// The trust directory arrives as the descriptor the caller already holds rather
/// than as a name to resolve: opening `trust/` again would let a home repointed
/// mid-command answer the authorization question from another tree. A caller
/// without one has no store to read, which is the normal first run.
pub(crate) fn load_verified_local_trust_store(
    home: &AnchoredDir,
    trust_dir: Option<&OpenDir>,
    owner: MemberHandle,
    keystore: Option<&KeystoreAccess>,
) -> Result<Option<VerifiedLocalTrustStoreLoadResult>> {
    let Some(trust_dir) = trust_dir else {
        return Ok(None);
    };
    LocalTrustStore::open_from_anchored_base(home, owner).load_verified_at(trust_dir, keystore)
}

/// Apply one mutation through an explicit trust command session.
pub(crate) fn execute_trust_store_mutation_with_session<T, F>(
    session: &TrustCommandSession,
    mutate: F,
) -> Result<T>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    let resolved = resolve_session_trust_mutation(session)?;
    let signing = build_signing_context(session.key_ctx().inner())?;
    let observed = resolved.observe()?;
    commit_trust_store_mutation(
        &resolved.target(&signing),
        observed.prepared(),
        TrustStoreCommitGate::ReviewedContent,
        mutate,
    )
    .map(|outcome| outcome.value)
}

/// What one explicit re-signing did to the stored signature.
pub(crate) struct TrustStoreResignOutcome {
    pub(crate) previous_signer_kid: Kid,
    pub(crate) signer_kid: String,
    pub(crate) write: TrustStoreWrite,
}

/// A re-signing that has been resolved and observed but not yet written.
///
/// Both keys the write turns on are known once the store has been observed, so
/// a caller whose own conditions depend on them can refuse while the stored
/// signature is still the one its decision was made against. A signature that
/// has already moved cannot be put back by the command that fails afterwards.
pub(crate) struct TrustStoreResignPlan<'a> {
    resolved: TrustMutationResolution<'a>,
    signing: VerifiedSigningContext<'a>,
    observed: ObservedTrustStore,
    previous_signer_kid: Kid,
}

impl TrustStoreResignPlan<'_> {
    /// The key the stored signature named when it was observed.
    pub(crate) fn previous_signer_kid(&self) -> &Kid {
        &self.previous_signer_kid
    }

    /// The key this re-signing would move the signature to.
    pub(crate) fn next_signer_kid(&self) -> &str {
        self.signing.signer_kid()
    }

    /// Take the exclusive lock and persist the signature the plan named.
    ///
    /// The content is left exactly as stored, so the mutation reports no change
    /// and only a signer that no longer matches produces a write.
    pub(crate) fn commit(self) -> Result<TrustStoreResignOutcome> {
        let outcome = commit_trust_store_mutation(
            &self.resolved.target(&self.signing),
            self.observed.prepared(),
            TrustStoreCommitGate::ReviewedContent,
            |_| {
                Ok(TrustStoreMutation {
                    value: (),
                    changed: false,
                })
            },
        )?;
        Ok(TrustStoreResignOutcome {
            previous_signer_kid: self.previous_signer_kid,
            signer_kid: outcome.signer_kid,
            write: outcome.write,
        })
    }
}

/// Re-sign the stored trust store through an explicit trust command session.
pub(crate) fn execute_trust_store_resign_with_session(
    session: &TrustCommandSession,
) -> Result<TrustStoreResignOutcome> {
    let resolved = resolve_session_trust_mutation(session)?;
    let signing = build_signing_context(session.key_ctx().inner())?;
    let observed = resolved.observe()?;
    let previous_signer_kid = observed
        .stored()
        .ok_or_else(|| build_trust_store_not_found_error(session.owner().as_str()))?
        .signer_kid
        .clone();
    TrustStoreResignPlan {
        resolved,
        signing,
        observed,
        previous_signer_kid,
    }
    .commit()
}

/// The local state a caller already opened and a later step must act through.
///
/// A key command opens the home, the keystore and the trust directory once and
/// decides the removal against what they hold. The signing identity is resolved
/// afterwards, from the configured path rather than from those descriptors, so
/// a path repointed in between would have the re-signing act on another tree
/// while the decision was made about this one.
pub(crate) struct LocalStateBinding<'a> {
    home: &'a AnchoredDir,
    keystore: &'a KeystoreAccess,
    trust_dir: Option<&'a OpenDir>,
}

impl<'a> LocalStateBinding<'a> {
    pub(crate) fn new(
        home: &'a AnchoredDir,
        keystore: &'a KeystoreAccess,
        trust_dir: Option<&'a OpenDir>,
    ) -> Self {
        Self {
            home,
            keystore,
            trust_dir,
        }
    }

    fn ensure_session_matches(&self, session: &TrustCommandSession) -> Result<()> {
        ensure_same_directory(self.home, session.home(), "local state root")?;
        ensure_same_directory(
            self.keystore.root_dir(),
            session.keystore().root_dir(),
            "local keystore directory",
        )?;
        ensure_same_optional_directory(
            self.trust_dir,
            session.trust_dir().map(Arc::as_ref),
            "local trust directory",
        )
    }
}

fn ensure_same_directory<A, B>(expected: &A, current: &B, subject: &str) -> Result<()>
where
    A: DirectoryFd,
    B: DirectoryFd,
{
    if open_dir_identity(expected)? == open_dir_identity(current)? {
        return Ok(());
    }
    Err(build_rebound_local_state_error(subject))
}

/// A directory that is absent on one side and present on the other is a change
/// of tree just as much as two different inodes are.
fn ensure_same_optional_directory(
    expected: Option<&OpenDir>,
    current: Option<&OpenDir>,
    subject: &str,
) -> Result<()> {
    match (expected, current) {
        (None, None) => Ok(()),
        (Some(expected), Some(current)) => ensure_same_directory(expected, current, subject),
        _ => Err(build_rebound_local_state_error(subject)),
    }
}

fn build_rebound_local_state_error(subject: &str) -> Error {
    Error::build_invalid_operation_error(format!(
        "The {subject} this command opened is not the one its signing identity resolved, so \
         re-signing now would act on a different local trust store. Run the command again."
    ))
}

/// Plan a re-signing through an explicit session bound to the key removal's local state.
pub(crate) fn plan_trust_store_resign_bound_session<'a>(
    session: &'a TrustCommandSession,
    binding: &LocalStateBinding<'_>,
) -> Result<TrustStoreResignPlan<'a>> {
    binding.ensure_session_matches(session)?;
    let resolved = resolve_session_trust_mutation(session)?;
    let signing = build_signing_context(session.key_ctx().inner())?;
    let observed = resolved.observe()?;
    let previous_signer_kid = observed
        .stored()
        .ok_or_else(|| build_trust_store_not_found_error(session.owner().as_str()))?
        .signer_kid
        .clone();
    Ok(TrustStoreResignPlan {
        resolved,
        signing,
        observed,
        previous_signer_kid,
    })
}

/// Which key the stored trust store's signature was verified against.
///
/// Content that will not verify names no key and rules none out either, so it
/// is reported apart from an absent store: a caller deciding whether a key may
/// be removed has to tell the two cases apart.
pub(crate) enum TrustSignerRecord {
    /// The stored document verified against this key.
    Signer(String),
    /// There is no stored trust store to carry a signature.
    Absent,
    /// The stored content did not verify, carrying why it did not.
    Unreadable(Error),
}

/// Verify the stored trust store and report the key it was signed with.
///
/// `signature.kid` is outside the signed bytes, so the field on its own says
/// nothing: rewriting it to name a key that stays would make the key that
/// actually signed look unrelated and removable, and the stored approvals
/// would stop verifying for good. Only a document that verified end to end
/// names its signer here.
///
/// The canonical document is read before the keystore is consulted; both are
/// ordinary published-snapshot reads.
///
/// `keystore` is the one a caller already opened. Passing it keeps the keys the
/// signature is verified against in the very keystore the caller decided
/// against: leaving it out reopens the configured path, and a `keys` directory
/// swapped in meanwhile would answer with another tree's keys.
///
/// Every way the read can end is one of the three answers, so nothing is left
/// for a caller to handle: a failure is the `Unreadable` answer rather than a
/// failure of this call.
pub(crate) fn load_stored_trust_signer(
    base: &AnchoredDir,
    trust_dir: Option<&OpenDir>,
    owner: &MemberHandle,
    keystore: Option<&KeystoreAccess>,
) -> TrustSignerRecord {
    match load_optional_trust_store(base, trust_dir, owner, keystore) {
        Ok(Some(state)) => verified_trust_signer(state),
        Ok(None) => TrustSignerRecord::Absent,
        Err(error) => TrustSignerRecord::Unreadable(error),
    }
}

/// Name the key a verified document was signed with.
///
/// Verification resolves the signer key before it accepts anything, so a state
/// that came back verified always carries one.
fn verified_trust_signer(state: TrustStoreState) -> TrustSignerRecord {
    state.signer_kid.map_or_else(
        || {
            TrustSignerRecord::Unreadable(Error::build_invalid_operation_error(
                "Verified local trust store carried no signer key".to_string(),
            ))
        },
        |kid| TrustSignerRecord::Signer(kid.into_string()),
    )
}

/// Observe the document an explicit trust command will mutate.
pub(crate) fn observe_session_trust_store(
    session: &TrustCommandSession,
) -> Result<ObservedTrustStore> {
    resolve_session_trust_mutation(session)?.observe()
}

/// Commit a reviewed mutation through an explicit trust command session.
pub(crate) fn execute_trust_store_mutation_with_session_preparation_reporting_resign<T, F>(
    session: &TrustCommandSession,
    prepared: &TrustStorePreparation,
    mutate: F,
) -> Result<(T, bool)>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    let resolved = resolve_session_trust_mutation(session)?;
    let signing = build_signing_context(session.key_ctx().inner())?;
    commit_trust_store_mutation(
        &resolved.target(&signing),
        prepared,
        TrustStoreCommitGate::ReviewedContent,
        mutate,
    )
    .map(|outcome| (outcome.value, outcome.write == TrustStoreWrite::Resign))
}

// Test-only entry point: the session sequence with a hook in the window between
// the observation and the exclusive commit.
#[cfg(test)]
pub(crate) fn execute_trust_store_mutation_with_session_prepare_hook<T, F, H>(
    session: &TrustCommandSession,
    mutate: F,
    prepare_hook: H,
) -> Result<T>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
    H: FnOnce(),
{
    let resolved = resolve_session_trust_mutation(session)?;
    let signing = build_signing_context(session.key_ctx().inner())?;
    let observed = resolved.observe()?;
    prepare_hook();
    commit_trust_store_mutation(
        &resolved.target(&signing),
        observed.prepared(),
        TrustStoreCommitGate::ReviewedContent,
        mutate,
    )
    .map(|outcome| outcome.value)
}

fn resolve_session_trust_mutation(
    session: &TrustCommandSession,
) -> Result<TrustMutationResolution<'_>> {
    let trust_dir = session
        .trust_dir()
        .cloned()
        .ok_or_else(|| build_trust_store_not_found_error(session.owner().as_str()))?;
    Ok(TrustMutationResolution {
        base: session.home().clone(),
        trust_dir,
        path: session.path().to_path_buf(),
        keystore: session.keystore(),
        owner: session.owner().clone(),
        mode: TrustStoreMutationMode::ExistingRequired,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_trust_store_test.rs"]
mod service_trust_store_test;
