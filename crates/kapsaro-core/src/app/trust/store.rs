// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store load and mutation entry points bound to a command's execution context.
//! Resolves the capabilities one mutation writes through and hands them to the core.

use crate::api::trust::{LocalTrustStore, VerifiedLocalTrustStoreLoadResult};
use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::feature::context::crypto::{build_signing_context, VerifiedSigningContext};
use crate::feature::trust::store_mutation::{
    build_empty_trust_store, build_trust_store_not_found_error, TrustStoreMutation,
    TrustStoreMutationMode, TrustStoreMutationOutcome, TrustStoreMutationTarget, TrustStoreState,
    TrustStoreWrite,
};
use crate::feature::trust::transaction::{
    commit_trust_store_mutation, ObservedTrustStore, TrustStoreCommitGate, TrustStorePreparation,
};
use crate::io::keystore::access::{build_missing_keystore_error, KeystoreAccess};
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::attach_trust_store_recovery;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::TrustStoreProtected;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_dir_identity, DirectoryFd, OpenDir};
use crate::{Error, Result};
use std::path::PathBuf;
use std::sync::Arc;

/// How one command's write relates to the document it last read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustStoreWriteBinding {
    /// An argument-driven `trust` command, bound to the document it observed.
    ///
    /// A store that moved between the observation and the write is a conflict
    /// the operator re-runs. Content that cannot be verified before the lock is
    /// the local recovery route's own condition and reaches it.
    ObservedDocument,
    /// A write-back of key approvals, merged into whatever other writers left
    /// behind.
    ///
    /// Approving a key adds one record under its own kid, so two runs approving
    /// different keys each keep their approval and the stored bytes are not
    /// bound. A write-back that replaces a record rather than adding one has no
    /// such ground and binds itself to the document it observed.
    MergedApproval,
}

impl TrustStoreWriteBinding {
    fn gate(self) -> TrustStoreCommitGate {
        match self {
            Self::ObservedDocument => TrustStoreCommitGate::ReviewedContent,
            Self::MergedApproval => TrustStoreCommitGate::LatestContent,
        }
    }
}

/// Capabilities one CLI trust store mutation resolved before taking any lock.
struct ResolvedTrustMutation<'a> {
    base: AnchoredDir,
    trust_dir: Arc<OpenDir>,
    path: PathBuf,
    keystore: &'a KeystoreAccess,
    owner: MemberHandle,
    mode: TrustStoreMutationMode,
}

impl ResolvedTrustMutation<'_> {
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

    /// Observe the stored bytes and the signer key, each under its own lock.
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

/// Load and verify the trust store bound to the capabilities this command fixed.
///
/// A run without a local state home has no store to read, which is the normal
/// first run rather than a failure.
pub(crate) fn load_execution_trust_store(
    execution: &ExecutionContext,
) -> Result<Option<TrustStoreState>> {
    let Some(home) = execution.optional_local_state_home() else {
        return Ok(None);
    };
    let trust_dir = execution.opened_trust_directory()?;
    load_optional_trust_store(
        home,
        trust_dir.map(Arc::as_ref),
        &execution.member_handle,
        execution.key_ctx.inner().local_keystore_access(),
    )
}

/// Load and verify one trust store through its fixed local-state capability.
/// Returns `None` when the trust directory or the store file is absent.
///
/// The document is read under the trust directory's shared lock and that lock is
/// released before the keystore is consulted, so this reader never holds the
/// trust lock and a member lock at once.
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
/// a condition of that store, so every app-layer read of a trust store ends up
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

/// Apply one mutation to the trust store this command is bound to.
///
/// The whole transaction runs here: the stored bytes and the signer key are
/// observed under two separate shared locks, both released before the exclusive
/// commit is taken. What `binding` decides is how tightly the write is tied to
/// what was observed.
pub(crate) fn execute_trust_store_mutation_with_execution<T, F>(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
    binding: TrustStoreWriteBinding,
    mutate: F,
) -> Result<T>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    run_trust_store_mutation(options, execution, mode, binding, mutate, || {})
}

/// The one path every command-bound mutation runs, with `between` marking the
/// window between the observation and the exclusive commit.
///
/// Production passes a hook that does nothing, so there is a single sequence to
/// reason about rather than one production path and one a test approximates.
fn run_trust_store_mutation<T, F, Between>(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
    binding: TrustStoreWriteBinding,
    mutate: F,
    between: Between,
) -> Result<T>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
    Between: FnOnce(),
{
    let resolved = resolve_trust_store_mutation(execution, mode, || options.resolve_base_dir())?;
    let signing = build_signing_context(execution.key_ctx.inner())?;
    let observed = resolved.observe()?;
    between();
    commit_trust_store_mutation(
        &resolved.target(&signing),
        observed.prepared(),
        binding.gate(),
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
pub(crate) struct PlannedTrustStoreResign<'a> {
    resolved: ResolvedTrustMutation<'a>,
    signing: VerifiedSigningContext<'a>,
    observed: ObservedTrustStore,
    previous_signer_kid: Kid,
}

impl PlannedTrustStoreResign<'_> {
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

/// Resolve and observe the re-signing one execution names, writing nothing.
fn plan_trust_store_resign_with_execution<'a>(
    options: &CommonCommandOptions,
    execution: &'a ExecutionContext,
) -> Result<PlannedTrustStoreResign<'a>> {
    let resolved =
        resolve_trust_store_mutation(execution, TrustStoreMutationMode::ExistingRequired, || {
            options.resolve_base_dir()
        })?;
    let signing = build_signing_context(execution.key_ctx.inner())?;
    let observed = resolved.observe()?;
    let previous_signer_kid = observed
        .stored()
        .ok_or_else(|| build_trust_store_not_found_error(resolved.owner.as_str()))?
        .signer_kid
        .clone();
    Ok(PlannedTrustStoreResign {
        resolved,
        signing,
        observed,
        previous_signer_kid,
    })
}

/// Re-sign the stored trust store with this command's signing key.
pub(crate) fn execute_trust_store_resign_with_execution(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
) -> Result<TrustStoreResignOutcome> {
    plan_trust_store_resign_with_execution(options, execution)?.commit()
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

    /// Confirm an execution resolved the very directories this binding holds.
    fn ensure_matches(&self, execution: &ExecutionContext) -> Result<()> {
        ensure_same_directory(
            self.home,
            execution.fixed_local_state_home()?,
            "local state root",
        )?;
        ensure_same_directory(
            self.keystore.root_dir(),
            execution
                .require_local_keystore_access("local trust store re-signing")?
                .root_dir(),
            "local keystore directory",
        )?;
        ensure_same_optional_directory(
            self.trust_dir,
            execution.opened_trust_directory()?.map(Arc::as_ref),
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

/// Plan a re-signing, refusing an execution bound to another local state.
pub(crate) fn plan_trust_store_resign_bound<'a>(
    options: &CommonCommandOptions,
    execution: &'a ExecutionContext,
    binding: &LocalStateBinding<'_>,
) -> Result<PlannedTrustStoreResign<'a>> {
    binding.ensure_matches(execution)?;
    plan_trust_store_resign_with_execution(options, execution)
}

/// Which key the stored trust store's signature was verified against.
///
/// Content that will not verify names no key and rules none out either, so it
/// is reported apart from an absent store: a caller deciding whether a key may
/// be removed has to tell the two cases apart.
pub(crate) enum StoredTrustSigner {
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
/// The document is read under the trust directory's shared lock and that lock
/// is released before the keystore is consulted, so this never holds the trust
/// lock and a member lock at once.
///
/// `keystore` is the one a caller already opened. Passing it keeps the keys the
/// signature is verified against in the very keystore the caller decided
/// against: leaving it out reopens the configured path, and a `keys` directory
/// swapped in meanwhile would answer with another tree's keys.
///
/// Every way the read can end is one of the three answers, so nothing is left
/// for a caller to handle: a failure is the `Unreadable` answer rather than a
/// failure of this call.
pub(crate) fn read_stored_trust_signer(
    base: &AnchoredDir,
    trust_dir: Option<&OpenDir>,
    owner: &MemberHandle,
    keystore: Option<&KeystoreAccess>,
) -> StoredTrustSigner {
    match load_optional_trust_store(base, trust_dir, owner, keystore) {
        Ok(Some(state)) => verified_trust_signer(state),
        Ok(None) => StoredTrustSigner::Absent,
        Err(error) => StoredTrustSigner::Unreadable(error),
    }
}

/// Name the key a verified document was signed with.
///
/// Verification resolves the signer key before it accepts anything, so a state
/// that came back verified always carries one.
fn verified_trust_signer(state: TrustStoreState) -> StoredTrustSigner {
    state.signer_kid.map_or_else(
        || {
            StoredTrustSigner::Unreadable(Error::build_invalid_operation_error(
                "Verified local trust store carried no signer key".to_string(),
            ))
        },
        |kid| StoredTrustSigner::Signer(kid.into_string()),
    )
}

/// Observe the trust store a review will be based on.
///
/// The observation travels with what the review produced, so the write-back
/// commits against the same bytes and the same signer key. `mode` is the one
/// the write-back will use, so a mutation that may create the store observes
/// through the directory it will create rather than reporting it missing.
pub(crate) fn observe_execution_trust_store(
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
) -> Result<ObservedTrustStore> {
    resolve_execution_trust_mutation(execution, mode)?.observe()
}

/// Commit one mutation against a trust store observed earlier, reporting how
/// the write reached the stored document alongside the mutation's value.
///
/// Most callers only need the value; `execute_trust_store_mutation_with_preparation`
/// covers those. A caller whose reported outcome depends on whether the write
/// only moved the signature onto today's key — a purge that removed nothing
/// can still do that — needs `write` too, so it goes through this instead.
fn commit_trust_store_mutation_with_preparation<T, F>(
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
    prepared: &TrustStorePreparation,
    mutate: F,
) -> Result<TrustStoreMutationOutcome<T>>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    let resolved = resolve_execution_trust_mutation(execution, mode)?;
    let signing = build_signing_context(execution.key_ctx.inner())?;
    commit_trust_store_mutation(
        &resolved.target(&signing),
        prepared,
        TrustStoreCommitGate::ReviewedContent,
        mutate,
    )
}

/// Commit one mutation against a trust store observed earlier.
pub(crate) fn execute_trust_store_mutation_with_preparation<T, F>(
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
    prepared: &TrustStorePreparation,
    mutate: F,
) -> Result<T>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    commit_trust_store_mutation_with_preparation(execution, mode, prepared, mutate)
        .map(|outcome| outcome.value)
}

/// Commit one mutation against a trust store observed earlier, also reporting
/// whether the write re-signed the store under a different key.
pub(crate) fn execute_trust_store_mutation_with_preparation_reporting_resign<T, F>(
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
    prepared: &TrustStorePreparation,
    mutate: F,
) -> Result<(T, bool)>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    commit_trust_store_mutation_with_preparation(execution, mode, prepared, mutate)
        .map(|outcome| (outcome.value, outcome.write == TrustStoreWrite::Resign))
}

// Test-only entry point: the production sequence with a hook in the window
// between the observation and the exclusive commit, so a test can change the
// stored state exactly where the transaction is built to detect it.
#[cfg(test)]
pub(crate) fn execute_trust_store_mutation_with_prepare_hook<T, F, H>(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
    binding: TrustStoreWriteBinding,
    mutate: F,
    prepare_hook: H,
) -> Result<T>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
    H: FnOnce(),
{
    run_trust_store_mutation(options, execution, mode, binding, mutate, prepare_hook)
}

fn resolve_execution_trust_mutation(
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
) -> Result<ResolvedTrustMutation<'_>> {
    resolve_trust_store_mutation(execution, mode, || {
        execution
            .fixed_local_state_home()
            .map(|home| home.path().to_path_buf())
    })
}

fn resolve_trust_store_mutation<ResolveBaseDir>(
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
    resolve_base_dir: ResolveBaseDir,
) -> Result<ResolvedTrustMutation<'_>>
where
    ResolveBaseDir: FnOnce() -> Result<PathBuf>,
{
    let keystore = require_execution_keystore(execution, resolve_base_dir)?;
    let base = execution.fixed_local_state_home()?.clone();
    let owner = execution.member_handle.clone();
    let path = get_trust_store_file_path(base.path(), &owner);
    let trust_dir = resolve_mutation_trust_directory(execution, mode)?;
    Ok(ResolvedTrustMutation {
        base,
        trust_dir,
        path,
        keystore,
        owner,
        mode,
    })
}

/// Open the trust directory this mutation writes into.
///
/// Only a mutation that may create the store creates the directory: a command
/// that requires an existing store reports it missing instead of leaving an
/// empty directory behind.
fn resolve_mutation_trust_directory(
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
) -> Result<Arc<OpenDir>> {
    match mode {
        TrustStoreMutationMode::CreateIfMissing => execution.ensured_trust_directory().cloned(),
        TrustStoreMutationMode::ExistingRequired => execution
            .opened_trust_directory()?
            .cloned()
            .ok_or_else(|| build_trust_store_not_found_error(execution.member_handle.as_str())),
    }
}

/// Keystore capability every trust store mutation writes through.
///
/// The location is only needed to report the failure, so it is resolved on the
/// failing branch alone: a command that has its keystore never depends on the
/// configured base directory resolving at all. The home this command fixed is
/// what every entry point reports, so the same failure names the same keys
/// directory; `resolve_base_dir` names it for a run that fixed no home.
fn require_execution_keystore<ResolveBaseDir>(
    execution: &ExecutionContext,
    resolve_base_dir: ResolveBaseDir,
) -> Result<&KeystoreAccess>
where
    ResolveBaseDir: FnOnce() -> Result<PathBuf>,
{
    if let Some(keystore) = execution.key_ctx.inner().local_keystore_access() {
        return Ok(keystore);
    }
    let base_dir = match execution.optional_local_state_home() {
        Some(home) => home.path().to_path_buf(),
        None => resolve_base_dir()?,
    };
    Err(build_missing_keystore_error(
        &get_keystore_root_from_base(&base_dir),
        &execution.member_handle,
    ))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_store_test.rs"]
mod tests;
