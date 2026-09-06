// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Non-interactive local trust store service.
//! Exposes trust evaluation and lock-coordinated local persistence.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::feature::context::crypto::{build_signing_context, VerifiedSigningContext};
use crate::feature::trust::judgment::{
    build_active_members_by_kid, enforce_signer_judgment, judge_recipients_trust,
    judge_signer_trust, ActiveMemberSnapshot, CurrentKeyMatch, KidSetMatch, KnownKeyCache,
    SelfTrustSet, SignerAcceptance, TrustIdentity, TrustJudgment,
};
use crate::feature::trust::known_keys::{add_known_key, KnownKeyIdentity};
use crate::feature::trust::recipient_sets::{
    file_recipient_evidence, find_inactive_recipient_kid, find_recipient_handle_mismatch,
    is_self_only_recipient_set, judge_recipient_set, kv_recipient_evidence, upsert_recipient_set,
    ArtifactRecipientSet, RecipientSetJudgment,
};
use crate::feature::trust::signer_keys::document_signer_kid;
use crate::feature::trust::store_mutation::{TrustStoreMutation, TrustStoreState};
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
};
use crate::io::keystore::access::{build_local_keystore_capability_error, KeystoreAccess};
use crate::io::trust::paths::{get_trust_store_file_path, TRUST_DIR_NAME};
use crate::io::trust::store::{
    attach_trust_store_recovery, load_trust_store_snapshot, TrustStoreSnapshot,
};
use crate::io::workspace::members::{load_active_member_files, load_active_member_files_at};
use crate::model::identity::Kid;
use crate::model::public_key::PublicKey;
use crate::model::public_key::VerifiedSigningPublicKey;
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, KnownKeyEvidence, KnownKeyGithubAccount, RecipientHandleHint,
    RecipientSetRecord, TrustStoreProtected,
};
use crate::model::trust_store_verified::VerifiedTrustStore;
use crate::model::verification::SignatureVerificationProof;
use crate::model::{file_enc::VerifiedFileEncDocument, kv_enc::verified::VerifiedKvEncDocument};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock::LockTargetDirectory;
use crate::support::fs::relative::{
    ensure_child_dir_restricted_at, open_optional_child_dir, DirectoryFd, DirectoryScope, OpenDir,
};
use crate::support::time::generate_current_timestamp;
use crate::support::warning::LocalStateWarningCapture;
use crate::{Error, ErrorKind, Result};

use crate::service::artifact::verified::{
    EncArtifactKind, ReadableEncArtifact, VerifiedEncArtifact,
};
use crate::service::diagnostics::{self, DiagnosticBatch};
use crate::service::file::{FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact};
use crate::service::key::{KeyContext, LocalKeyStore, MemberHandle, RecipientKeys};
use crate::service::kv::{
    AuthorizedKvMutation, KvMutationOperation, KvReadOperation, TrustedKvEncArtifact,
    VerifiedKvEncArtifact,
};
use crate::service::operation::OperationOptions;
use crate::service::rewrap::{AuthorizedRewrapInput, RewrapAcceptance, RewrapOptions};
use crate::service::trust::outcome::ArtifactRecipientSetSnapshot;
use crate::service::trust::persistence::{TrustStoreMutationMode, TrustStoreMutationTarget};
use crate::service::trust::transaction::{
    commit_trust_store_mutation, resolve_owner_keystore, verify_trust_store_with_owner_keys,
    ObservedTrustStore, TrustStoreCommitGate, TrustStorePreparation,
};

/// Operation name used when a trust store approval needs a local keystore.
const TRUST_STORE_APPROVAL_SUBJECT: &str = "Trust store approval";

/// Filesystem-backed local trust store for one owner.
#[derive(Clone)]
pub struct LocalTrustStore {
    base_dir: AnchoredDir,
    owner_handle: MemberHandle,
}

impl std::fmt::Debug for LocalTrustStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalTrustStore")
            .finish_non_exhaustive()
    }
}

/// Pure trust policy evaluator.
#[derive(Debug, Clone)]
pub struct TrustPolicyEvaluator {
    members: CurrentMemberSnapshot,
    store: Option<VerifiedLocalTrustStore>,
}

/// Signature-verified current workspace member state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentMemberSnapshot {
    members_by_kid: BTreeMap<String, PublicKey>,
}

/// Whether a read requires known-key review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownKeyReview {
    Required,
    Skipped,
}

/// Read controls consumed by a single low-level trust evaluation.
///
/// A non-member acceptance is minted by `WorkspaceReadSession` from opaque
/// review state; external callers cannot construct one from raw identities.
///
/// ```compile_fail
/// use kapsaro_core::api::key::{Kid, MemberHandle};
/// use kapsaro_core::api::trust::ReadTrustExceptions;
///
/// let handle = MemberHandle::try_from("alice@example.com").unwrap();
/// let kid = Kid::try_from("0123456789ABCDEFGHJKMNPQRSTVWXYZ").unwrap();
/// let _forged = ReadTrustExceptions::none().accepting_non_member(handle, kid);
/// ```
#[derive(Debug)]
pub struct ReadTrustExceptions {
    known_key_review: KnownKeyReview,
    accepted_non_member: Option<(MemberHandle, Kid)>,
}

/// Signature-verified local trust store.
#[derive(Debug, Clone)]
pub struct VerifiedLocalTrustStore {
    inner: VerifiedTrustStore,
}

/// Recipient-set subject extracted from a verified artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSetSubject {
    inner: ArtifactRecipientSet,
    recipient_kids: Vec<Kid>,
}

/// Non-interactive trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision<T = ()> {
    Trusted(T),
    ReviewRequired(Vec<TrustReviewRequest>),
}

/// Review request returned to the caller instead of prompting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustReviewRequest {
    kind: TrustReviewKind,
    subject_handle: Option<MemberHandle>,
    kid: Option<Kid>,
    known_key_candidate: Option<KnownKeyReviewCandidate>,
    sid: Option<uuid::Uuid>,
    recipient_kids: Vec<Kid>,
    recipient_handle_hints: Vec<TrustRecipientHandleHint>,
    approved_recipient_set: Option<ArtifactRecipientSetSnapshot>,
}

/// Display-only recipient identity captured for recipient-set review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRecipientHandleHint {
    kid: Kid,
    recipient_handle: MemberHandle,
}

/// A verified public key presented for known-key review.
#[derive(Clone, PartialEq, Eq)]
pub struct KnownKeyReviewCandidate {
    public_key: PublicKey,
    subject_handle: MemberHandle,
    kid: Kid,
    fingerprint: Option<String>,
}

impl std::fmt::Debug for KnownKeyReviewCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KnownKeyReviewCandidate")
            .field("subject_handle", &self.subject_handle)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Evidence collected while approving a known key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownKeyApprovalEvidence {
    verified_github: Option<crate::service::online::VerifiedGitHubEvidence>,
    ssh_attestor_public_key: Option<String>,
}

/// Result of applying trust approvals.
#[derive(Debug)]
pub struct TrustApprovalOutcome {
    applied: usize,
    warnings: DiagnosticBatch,
}

/// Review request category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustReviewKind {
    KnownKey,
    RecipientSet,
    ChangedRecipientSet,
}

/// Internal read preflight result kept outside the public API contract.
#[derive(Debug)]
pub(crate) struct ReadTrustReview {
    requests: Vec<TrustReviewRequest>,
    signer_request_count: usize,
    non_member_signer: Option<NonMemberSignerReview>,
    unresolved_recipient_kids: Vec<Kid>,
    recipient_error: Option<crate::Error>,
}

/// Verified non-member signer material for a caller-controlled one-shot review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NonMemberSignerReview {
    candidate: KnownKeyReviewCandidate,
    recipient_handles: Vec<MemberHandle>,
}

/// Caller-approved trust update.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustApproval {
    kind: TrustApprovalKind,
}

#[derive(Debug, Clone, PartialEq)]
enum TrustApprovalKind {
    KnownKey(Box<KnownKeyApproval>),
    RecipientSet(RecipientSetApproval),
}

/// Opaque conflict policy for applying caller-approved trust updates.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ApprovalConflictHandling {
    policy: ApprovalConflictPolicy,
}

#[derive(Debug, Clone)]
enum ApprovalConflictPolicy {
    Merge,
    Surface(TrustStoreSurfaceSnapshot),
}

/// The content one caller reviewed, with the key it was verified against.
///
/// The commit accepts nothing but this content, so the signer it names is the
/// only key the write-back can need. A reviewed absence names none.
#[derive(Debug, Clone)]
struct TrustStoreSurfaceSnapshot {
    snapshot: TrustStoreSnapshot,
    signer_kid: Option<Kid>,
}

impl ApprovalConflictHandling {
    /// Serialize the update with other writers and merge it into the latest state.
    pub fn merge() -> Self {
        Self {
            policy: ApprovalConflictPolicy::Merge,
        }
    }

    /// Build conflict handling that binds the update to verified reviewed content.
    pub fn surface(reviewed: &VerifiedLocalTrustStoreLoadResult) -> Self {
        Self {
            policy: ApprovalConflictPolicy::Surface(TrustStoreSurfaceSnapshot {
                snapshot: reviewed.snapshot.clone(),
                signer_kid: reviewed.signer_kid.clone(),
            }),
        }
    }

    /// Build conflict handling that binds the update to a reviewed absence.
    ///
    /// `load_verified` reports "there is no store" as `None`, which carries no
    /// content to bind to. A caller that decided on the strength of that answer
    /// says so here, and the update is refused if a store has appeared since.
    pub fn surface_absent() -> Self {
        Self {
            policy: ApprovalConflictPolicy::Surface(TrustStoreSurfaceSnapshot {
                snapshot: TrustStoreSnapshot::Missing,
                signer_kid: None,
            }),
        }
    }
}

/// Caller-approved known-key trust update.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KnownKeyApproval {
    candidate: KnownKeyReviewCandidate,
    evidence: KnownKeyApprovalEvidence,
}

/// Caller-approved recipient-set trust update.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecipientSetApproval {
    sid: uuid::Uuid,
    recipient_kids: Vec<Kid>,
    recipient_handle_hints: Vec<TrustRecipientHandleHint>,
}

/// Capabilities one caller-approved trust update writes through.
struct ApprovalMutationContext<'a> {
    signing: VerifiedSigningContext<'a>,
    keystore: &'a KeystoreAccess,
    trust_dir: &'a OpenDir,
    path: PathBuf,
}

impl ReadTrustExceptions {
    /// Build a fail-closed read policy.
    pub fn none() -> Self {
        Self {
            known_key_review: KnownKeyReview::Required,
            accepted_non_member: None,
        }
    }

    /// Select whether this read requires known-key review.
    pub fn with_known_key_review(mut self, review: KnownKeyReview) -> Self {
        self.known_key_review = review;
        self
    }

    /// Accept exactly one session-reviewed non-member signer identity.
    pub(crate) fn accepting_non_member(mut self, member_handle: MemberHandle, kid: Kid) -> Self {
        self.accepted_non_member = Some((member_handle, kid));
        self
    }

    /// Return whether a reviewed non-member signer identity is accepted.
    pub(crate) fn has_accepted_non_member(&self) -> bool {
        self.accepted_non_member.is_some()
    }
}

/// Loaded and verified local trust store, bound to the content it was read from.
#[derive(Debug)]
pub struct VerifiedLocalTrustStoreLoadResult {
    store: VerifiedLocalTrustStore,
    /// The exact content this result was verified from, for `surface`.
    snapshot: TrustStoreSnapshot,
    /// The key that content verified against, for `surface`.
    signer_kid: Option<Kid>,
}

impl LocalTrustStore {
    /// Open a trust store facade from an existing `<KAPSARO_HOME>` directory.
    pub fn open(base_dir: impl Into<PathBuf>, owner_handle: MemberHandle) -> Result<Self> {
        let base_dir = AnchoredDir::open(base_dir, DirectoryScope::LocalState, "local state root")?;
        Ok(Self {
            base_dir,
            owner_handle,
        })
    }

    pub(crate) fn open_from_anchored_base(
        base_dir: &AnchoredDir,
        owner_handle: MemberHandle,
    ) -> Self {
        Self {
            base_dir: base_dir.clone(),
            owner_handle,
        }
    }

    /// Open a restricted `<KAPSARO_HOME>` directory, creating it when absent.
    pub fn ensure(base_dir: impl Into<PathBuf>, owner_handle: MemberHandle) -> Result<Self> {
        let base_dir =
            AnchoredDir::ensure(base_dir, DirectoryScope::LocalState, "local state root")?;
        Ok(Self {
            base_dir,
            owner_handle,
        })
    }

    /// Return the backing trust store file path.
    pub fn path(&self) -> PathBuf {
        get_trust_store_file_path(self.base_dir.path(), &self.owner_handle)
    }

    /// Load and verify the local trust store through a local keystore.
    ///
    /// A failure the stored document itself caused — malformed JSON, a schema
    /// mismatch, a bad signature — arrives as what it was, and names deleting
    /// the store through [`Error::recovery`] as the route past it. The two are
    /// independent, so an embedding application that logs a schema mismatch
    /// differently from a forged signature reads that from [`Error::kind`]
    /// without having to give up the recovery route.
    pub fn load_verified(
        &self,
        key_store: &LocalKeyStore,
    ) -> Result<Option<VerifiedLocalTrustStoreLoadResult>> {
        self.load_verified_with_access(Some(key_store.access()))
    }

    pub(crate) fn load_verified_with_access(
        &self,
        keystore: Option<&KeystoreAccess>,
    ) -> Result<Option<VerifiedLocalTrustStoreLoadResult>> {
        let Some(trust_dir) = open_optional_child_dir(&self.base_dir, TRUST_DIR_NAME)
            .map_err(|error| attach_trust_store_recovery(&self.path(), error))?
        else {
            return Ok(None);
        };
        self.load_verified_at(&trust_dir, keystore)
    }

    /// Load and verify the store held under one trust directory descriptor.
    ///
    /// A command that already opened its trust directory reads through that
    /// descriptor rather than through the name: resolving the name a second
    /// time would let a directory repointed mid-command answer the same
    /// question from another tree.
    ///
    /// The whole read carries one recovery route, applied once around it, so a
    /// caller reaches the same route whether the bytes would not parse or the
    /// signature over them did not verify.
    pub(crate) fn load_verified_at<D>(
        &self,
        trust_dir: &D,
        keystore: Option<&KeystoreAccess>,
    ) -> Result<Option<VerifiedLocalTrustStoreLoadResult>>
    where
        D: DirectoryFd + LockTargetDirectory,
    {
        let path = self.path();
        self.verify_stored_trust_store_at(trust_dir, keystore, &path)
            .map_err(|error| attach_trust_store_recovery(&path, error))
    }

    /// Read the stored bytes and verify them against the owner's signer keys.
    ///
    /// Opening the keystore is a capability of its own and its failures name
    /// the keys directory, so those travel as they are: describing them against
    /// the trust store would send the operator to a file that is not what is
    /// wrong. They already name their own repair, which is what keeps them out
    /// of the reset offer wrapped around this.
    fn verify_stored_trust_store_at<D>(
        &self,
        trust_dir: &D,
        keystore: Option<&KeystoreAccess>,
        path: &Path,
    ) -> Result<Option<VerifiedLocalTrustStoreLoadResult>>
    where
        D: DirectoryFd + LockTargetDirectory,
    {
        let Some(loaded) = load_trust_store_snapshot(&self.base_dir, trust_dir, path)? else {
            return Ok(None);
        };
        let keystore = resolve_owner_keystore(keystore, &self.base_dir, &self.owner_handle)?;
        let snapshot = TrustStoreSnapshot::from_loaded(Some(&loaded));
        let signer_kid = document_signer_kid(&loaded.document);
        let store = verify_trust_store_with_owner_keys(
            &loaded.document,
            keystore.as_ref(),
            &self.owner_handle,
        )?;
        Ok(Some(VerifiedLocalTrustStoreLoadResult {
            store: VerifiedLocalTrustStore::from_inner(store),
            snapshot,
            signer_kid,
        }))
    }

    /// Apply caller-approved updates, re-sign, and save atomically.
    ///
    /// Conflict handling is always stated: a caller that approved on the
    /// strength of content it showed a person binds the update to that content
    /// with `surface`, while `merge` only serializes against other writers.
    ///
    /// The two also part company over a stored store that no longer reads back
    /// at all. `surface` calls that a conflict, because the operator was shown
    /// something and content that will not read back is proof it is no longer
    /// what they approved. `merge` showed nobody anything, so it reports the
    /// store as the store it is, with the route back.
    pub fn apply_approvals_with_conflict_handling(
        &self,
        approvals: Vec<TrustApproval>,
        key_ctx: &KeyContext,
        conflict_handling: ApprovalConflictHandling,
    ) -> Result<TrustApprovalOutcome> {
        let capture = LocalStateWarningCapture::new();
        let trust_dir = ensure_child_dir_restricted_at(&self.base_dir, TRUST_DIR_NAME)?;
        let applied = self.apply_approvals_at(&trust_dir, approvals, key_ctx, conflict_handling)?;
        Ok(TrustApprovalOutcome {
            applied,
            warnings: diagnostics::from_warning_batch(capture.finish()),
        })
    }

    pub(crate) fn apply_approvals_with_conflict_handling_at(
        &self,
        trust_dir: &OpenDir,
        approvals: Vec<TrustApproval>,
        key_ctx: &KeyContext,
        conflict_handling: ApprovalConflictHandling,
    ) -> Result<TrustApprovalOutcome> {
        let capture = LocalStateWarningCapture::new();
        let applied = self.apply_approvals_at(trust_dir, approvals, key_ctx, conflict_handling)?;
        Ok(TrustApprovalOutcome {
            applied,
            warnings: diagnostics::from_warning_batch(capture.finish()),
        })
    }

    fn apply_approvals_at(
        &self,
        trust_dir: &OpenDir,
        approvals: Vec<TrustApproval>,
        key_ctx: &KeyContext,
        conflict_handling: ApprovalConflictHandling,
    ) -> Result<usize> {
        match conflict_handling.policy {
            ApprovalConflictPolicy::Merge => {
                self.apply_approvals_merged(trust_dir, approvals, key_ctx)
            }
            ApprovalConflictPolicy::Surface(reviewed) => {
                self.apply_approvals_reviewed(trust_dir, approvals, key_ctx, reviewed)
            }
        }
    }

    /// Serialize with other writers and merge into whatever they left behind.
    ///
    /// The caller has not bound this update to content it showed anyone, so the
    /// commit takes the latest stored bytes rather than the observed ones. The
    /// observation still runs, because it reads the signer keys the commit
    /// verifies with.
    ///
    /// A store that does not verify at all is reported as what it is, with the
    /// route back, and both reads say so: the observation here, and the read
    /// the commit takes under the exclusive lock. Re-reading is all this gate
    /// does about content that moved, and no re-read makes an unusable store
    /// usable, so calling it a conflict would send the operator to run a
    /// command again that cannot come out differently.
    fn apply_approvals_merged(
        &self,
        trust_dir: &OpenDir,
        approvals: Vec<TrustApproval>,
        key_ctx: &KeyContext,
    ) -> Result<usize> {
        let context = self.build_mutation_context(trust_dir, key_ctx)?;
        let observed = self.observe(&context)?;
        commit_trust_store_mutation(
            &self.mutation_target(&context),
            observed.prepared(),
            TrustStoreCommitGate::LatestContent,
            |protected| self.apply_approvals_to(protected, approvals),
        )
        .map(|outcome| outcome.value)
    }

    /// Write back only onto the content the caller showed a person.
    ///
    /// The commit accepts the reviewed bytes and nothing else, so anything the
    /// exclusive lock finds in their place is a conflict, whether it is content
    /// another writer left or content that will not read back at all. Neither
    /// is what was approved, and the second is not offered as a store to reset:
    /// a store that can be broken between the review and the write would
    /// otherwise become a way to walk the operator into discarding approvals
    /// they never agreed to lose.
    fn apply_approvals_reviewed(
        &self,
        trust_dir: &OpenDir,
        approvals: Vec<TrustApproval>,
        key_ctx: &KeyContext,
        reviewed: TrustStoreSurfaceSnapshot,
    ) -> Result<usize> {
        let context = self.build_mutation_context(trust_dir, key_ctx)?;
        let prepared = TrustStorePreparation::from_reviewed_snapshot(
            reviewed.snapshot,
            reviewed.signer_kid.as_ref(),
            context.keystore,
            &self.owner_handle,
        )?;
        commit_trust_store_mutation(
            &self.mutation_target(&context),
            &prepared,
            TrustStoreCommitGate::ReviewedContent,
            |protected| self.apply_approvals_to(protected, approvals),
        )
        .map(|outcome| outcome.value)
    }

    /// Run steps 1 to 4 of the transaction for this facade's store.
    ///
    /// A store that will not verify names the same recovery route a load names
    /// it by, so a caller can tell a store needing a reset apart from any other
    /// failure whichever entry point it came in by, and still reads what the
    /// failure was from the kind either way.
    fn observe(&self, context: &ApprovalMutationContext<'_>) -> Result<ObservedTrustStore> {
        ObservedTrustStore::observe(
            &self.base_dir,
            context.trust_dir,
            &context.path,
            &self.owner_handle,
            context.keystore,
        )
        .map_err(|error| attach_trust_store_recovery(&context.path, error))
    }

    /// Bind the caller's opened trust directory and signing capabilities.
    fn build_mutation_context<'a>(
        &self,
        trust_dir: &'a OpenDir,
        key_ctx: &'a KeyContext,
    ) -> Result<ApprovalMutationContext<'a>> {
        self.ensure_owner_key_context(key_ctx)?;
        let signing = build_signing_context(key_ctx.inner())?;
        let keystore = self.require_local_keystore(key_ctx)?;
        Ok(ApprovalMutationContext {
            signing,
            keystore,
            trust_dir,
            path: self.path(),
        })
    }

    /// Bind the resolved capabilities to the key that signs this update.
    fn mutation_target<'a>(
        &'a self,
        context: &'a ApprovalMutationContext<'_>,
    ) -> TrustStoreMutationTarget<'a> {
        TrustStoreMutationTarget {
            base: &self.base_dir,
            trust_dir: context.trust_dir,
            path: &context.path,
            owner: &self.owner_handle,
            mode: TrustStoreMutationMode::CreateIfMissing,
            signing: &context.signing,
        }
    }

    fn require_local_keystore<'a>(&self, key_ctx: &'a KeyContext) -> Result<&'a KeystoreAccess> {
        key_ctx
            .inner()
            .local_keystore_access()
            .ok_or_else(|| build_local_keystore_capability_error(TRUST_STORE_APPROVAL_SUBJECT))
    }

    /// Apply every approval and report whether any of them moved the content.
    fn apply_approvals_to(
        &self,
        protected: &mut TrustStoreProtected,
        approvals: Vec<TrustApproval>,
    ) -> Result<TrustStoreMutation<usize>> {
        let mut applied = 0;
        for approval in approvals {
            applied += usize::from(self.apply_approval_update(protected, approval)?);
        }
        Ok(TrustStoreMutation {
            value: applied,
            changed: applied > 0,
        })
    }

    fn apply_approval_update(
        &self,
        protected: &mut TrustStoreProtected,
        approval: TrustApproval,
    ) -> Result<bool> {
        match approval.kind {
            TrustApprovalKind::KnownKey(key) => self.apply_known_key_approval(protected, *key),
            TrustApprovalKind::RecipientSet(approval) => {
                apply_recipient_set_approval(protected, approval)
            }
        }
    }

    fn apply_known_key_approval(
        &self,
        protected: &mut TrustStoreProtected,
        key: KnownKeyApproval,
    ) -> Result<bool> {
        let known_key = key.into_known_key(generate_current_timestamp()?)?;
        if known_key.subject_handle == self.owner_handle.as_str() {
            return Err(Error::build_invalid_operation_error(format!(
                "Self member '{}' must not be stored in known_keys",
                self.owner_handle
            )));
        }
        add_known_key(&mut protected.known_keys, known_key)
    }

    fn ensure_owner_key_context(&self, key_ctx: &KeyContext) -> Result<()> {
        if key_ctx.member_handle() != &self.owner_handle {
            return Err(Error::build_invalid_argument_error(format!(
                "Key context member_handle '{}' does not match trust store owner_handle '{}'",
                key_ctx.member_handle(),
                self.owner_handle
            )));
        }
        Ok(())
    }
}

fn apply_recipient_set_approval(
    protected: &mut TrustStoreProtected,
    approval: RecipientSetApproval,
) -> Result<bool> {
    let hints = approval
        .recipient_handle_hints
        .into_iter()
        .map(TrustRecipientHandleHint::into_model)
        .collect();
    let recipient_set = ArtifactRecipientSet::from_parts(
        approval.sid,
        approval
            .recipient_kids
            .into_iter()
            .map(Kid::into_string)
            .collect(),
        hints,
    )?;
    Ok(upsert_recipient_set(
        &mut protected.recipient_sets,
        recipient_set,
        generate_current_timestamp()?,
    ))
}

impl CurrentMemberSnapshot {
    /// Load and verify the current active members from a workspace path.
    ///
    /// An embedding application names its workspace by path, which is the only
    /// handle it has. A command that already bound its workspace to a
    /// descriptor loads through that instead, so the tree it authorizes against
    /// cannot change under it.
    pub fn load(workspace_path: &Path) -> Result<Self> {
        Self::from_active_members(load_active_member_files(workspace_path)?)
    }

    /// Load and verify the active members held under one workspace descriptor.
    pub(crate) fn load_at<D>(workspace: &D) -> Result<Self>
    where
        D: DirectoryFd,
    {
        Self::from_active_members(load_active_member_files_at(workspace)?)
    }

    fn from_active_members(members: Vec<PublicKey>) -> Result<Self> {
        if members.is_empty() {
            return Err(Error::build_not_found_error(
                "No active members found in workspace".to_string(),
            ));
        }
        let verified_members = members
            .iter()
            .map(|member| {
                verify_public_key_for_verification_context(
                    member,
                    WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
                )
                .map(|verified| verified.verified_public_key.document().clone())
            })
            .collect::<Result<Vec<_>>>()?;
        build_active_members_by_kid(&verified_members).map(|members_by_kid| Self { members_by_kid })
    }

    pub(crate) fn from_verified_members_by_kid(
        members_by_kid: BTreeMap<String, PublicKey>,
    ) -> Result<Self> {
        if members_by_kid.is_empty() {
            return Err(Error::build_not_found_error(
                "No active members found in workspace".to_string(),
            ));
        }
        build_active_members_by_kid(&members_by_kid.into_values().collect::<Vec<PublicKey>>())
            .map(|members_by_kid| Self { members_by_kid })
    }

    pub(crate) fn from_recipient_keys(recipients: &RecipientKeys) -> Result<Self> {
        let members = recipients
            .keys()
            .iter()
            .map(|key| key.document().clone())
            .collect::<Vec<_>>();
        build_active_members_by_kid(&members).map(|members_by_kid| Self { members_by_kid })
    }

    pub(crate) fn recipient_keys(&self) -> Result<RecipientKeys> {
        let public_keys = self.members_by_kid.values().cloned().collect::<Vec<_>>();
        let handles = public_keys
            .iter()
            .map(|key| key.protected.subject_handle.clone())
            .collect::<Vec<_>>();
        let verified =
            crate::feature::verify::public_key::verify_recipient_public_keys(&public_keys)?;
        RecipientKeys::from_verified_parts(handles, verified)
    }

    fn active_members(&self) -> ActiveMemberSnapshot<'_> {
        ActiveMemberSnapshot::new(&self.members_by_kid)
    }
}

impl TrustPolicyEvaluator {
    /// Build an evaluator from current members and an optional verified trust store.
    pub fn new(members: CurrentMemberSnapshot, store: Option<VerifiedLocalTrustStore>) -> Self {
        Self { members, store }
    }

    pub(crate) fn matches_state(&self, other: &Self) -> bool {
        self.members == other.members
            && self.store.as_ref().map(VerifiedLocalTrustStore::protected)
                == other.store.as_ref().map(VerifiedLocalTrustStore::protected)
    }

    pub(crate) fn known_keys(&self) -> &[KnownKey] {
        self.store
            .as_ref()
            .map(|store| store.protected().known_keys.as_slice())
            .unwrap_or_default()
    }

    pub(crate) fn self_trust(&self, key_ctx: &KeyContext) -> Result<SelfTrustSet> {
        build_self_trust(key_ctx)
    }

    /// Rebind this evaluator to a verified member snapshot while retaining the reviewed store.
    pub(crate) fn with_members(&self, members: CurrentMemberSnapshot) -> Self {
        Self {
            members,
            store: self.store.clone(),
        }
    }

    /// Evaluate and bind a verified file artifact to its read key.
    pub fn evaluate_file<'a>(
        &self,
        artifact: &'a VerifiedFileEncArtifact,
        key_ctx: &'a KeyContext,
        operation: FileReadOperation,
        options: OperationOptions,
        exceptions: ReadTrustExceptions,
    ) -> Result<TrustDecision<TrustedFileEncArtifact<'a>>> {
        let requests = self.evaluate_read_requests(artifact, key_ctx, &operation, &exceptions)?;
        if !requests.is_empty() {
            return Ok(TrustDecision::ReviewRequired(requests));
        }
        VerifiedFileEncArtifact::into_trusted(Cow::Borrowed(artifact), key_ctx, operation, options)
            .map(TrustDecision::Trusted)
    }

    /// Evaluate and bind a verified KV artifact to one read operation and key.
    pub fn evaluate_kv<'a>(
        &self,
        artifact: &'a VerifiedKvEncArtifact,
        key_ctx: &'a KeyContext,
        operation: KvReadOperation,
        options: OperationOptions,
        exceptions: ReadTrustExceptions,
    ) -> Result<TrustDecision<TrustedKvEncArtifact<'a>>> {
        let requests = self.evaluate_read_requests(artifact, key_ctx, &operation, &exceptions)?;
        if !requests.is_empty() {
            return Ok(TrustDecision::ReviewRequired(requests));
        }
        VerifiedKvEncArtifact::into_trusted(Cow::Borrowed(artifact), key_ctx, operation, options)
            .map(TrustDecision::Trusted)
    }

    /// Evaluate the trust reviews one read operation requires.
    ///
    /// The requests are returned without issuing a read capability, so a caller
    /// that resolves them evaluates the reloaded artifact again.
    pub(crate) fn evaluate_read_requests<A: ReadableEncArtifact>(
        &self,
        artifact: &A,
        key_ctx: &KeyContext,
        operation: &A::Operation,
        exceptions: &ReadTrustExceptions,
    ) -> Result<Vec<TrustReviewRequest>> {
        A::enforce_read_exceptions(operation, exceptions)?;
        let subject = artifact.recipient_set_subject()?;
        self.evaluate_read_artifact(artifact.proof(), &subject, key_ctx, exceptions)
    }

    /// Evaluate the trust reviews required before a read.
    ///
    /// This entry point returns review material without issuing a read
    /// capability. Environment reads pass `false` for `allow_non_member_review`
    /// because a one-shot non-member exception never authorizes them.
    pub(crate) fn preflight_read<A: VerifiedEncArtifact>(
        &self,
        artifact: &A,
        key_ctx: &KeyContext,
        known_key_review: KnownKeyReview,
        allow_non_member_review: bool,
    ) -> Result<ReadTrustReview> {
        let subject = artifact.recipient_set_subject()?;
        self.review_read_artifact(
            artifact.proof(),
            &subject,
            key_ctx,
            known_key_review,
            allow_non_member_review,
        )
    }

    /// Evaluate and bind a verified KV artifact to one mutation and output recipient set.
    ///
    /// This covers signer trust, current recipients, output recipient key trust, and output
    /// recipient-set approval before issuing the operation-bound capability.
    pub fn evaluate_kv_mutation<'a>(
        &self,
        artifact: &'a VerifiedKvEncArtifact,
        recipients: &'a RecipientKeys,
        key_ctx: &'a KeyContext,
        operation: KvMutationOperation,
        options: OperationOptions,
    ) -> Result<TrustDecision<AuthorizedKvMutation<'a>>> {
        let requests = self.kv_mutation_requests(artifact, recipients, key_ctx)?;
        if !requests.is_empty() {
            return Ok(TrustDecision::ReviewRequired(requests));
        }
        AuthorizedKvMutation::from_authorized(artifact, recipients, key_ctx, options, operation)
            .map(TrustDecision::Trusted)
    }

    /// Re-evaluate pre-promotion input trust and post-promotion output trust,
    /// then issue the only capability that can invoke rewrap.
    pub(crate) fn evaluate_rewrap<'a, A: VerifiedEncArtifact>(
        &self,
        input_evaluator: &TrustPolicyEvaluator,
        artifact: A,
        recipients: RecipientKeys,
        key_ctx: &'a KeyContext,
        options: RewrapOptions,
        acceptance: Option<RewrapAcceptance>,
    ) -> Result<TrustDecision<AuthorizedRewrapInput<'a>>> {
        let input = artifact.recipient_set_subject()?;
        let exceptions = self.rewrap_exceptions(
            input_evaluator,
            artifact.binding_digest(),
            A::KIND,
            options,
            artifact.proof(),
            &input,
            key_ctx,
            acceptance,
        )?;
        let requests = self.rewrap_requests(
            input_evaluator,
            artifact.proof(),
            &input,
            &recipients,
            key_ctx,
            &exceptions,
        )?;
        if !requests.is_empty() {
            return Ok(TrustDecision::ReviewRequired(requests));
        }
        AuthorizedRewrapInput::from_verified(artifact, recipients, key_ctx, options)
            .map(TrustDecision::Trusted)
    }

    #[allow(clippy::too_many_arguments)]
    fn rewrap_exceptions(
        &self,
        input_evaluator: &TrustPolicyEvaluator,
        digest: [u8; 32],
        artifact_kind: EncArtifactKind,
        options: RewrapOptions,
        proof: &SignatureVerificationProof,
        input: &RecipientSetSubject,
        key_ctx: &KeyContext,
        acceptance: Option<RewrapAcceptance>,
    ) -> Result<ReadTrustExceptions> {
        let Some(acceptance) = acceptance else {
            return Ok(ReadTrustExceptions::none());
        };
        let review = input_evaluator.review_read_artifact(
            proof,
            input,
            key_ctx,
            KnownKeyReview::Required,
            true,
        )?;
        let non_member = review.non_member_signer().ok_or_else(|| {
            Error::build_verification_error(
                "E_TRUST_TARGET_CHANGED".to_string(),
                "Reviewed rewrap signer trust changed. Run the command again.".to_string(),
            )
        })?;
        let signer = acceptance.validate(digest, artifact_kind, options, non_member.candidate())?;
        Ok(ReadTrustExceptions::none().accepting_non_member(signer.0, signer.1))
    }

    pub(crate) fn preflight_kv_mutation(
        &self,
        artifact: &VerifiedKvEncArtifact,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
    ) -> Result<TrustDecision> {
        let requests = self.kv_mutation_requests(artifact, recipients, key_ctx)?;
        if requests.is_empty() {
            Ok(TrustDecision::Trusted(()))
        } else {
            Ok(TrustDecision::ReviewRequired(requests))
        }
    }

    pub(crate) fn preflight_recipient_set(
        &self,
        recipient_set: &ArtifactRecipientSet,
        key_ctx: &KeyContext,
    ) -> Result<TrustDecision> {
        self.enforce_store_owner(key_ctx)?;
        let self_trust = build_self_trust(key_ctx)?;
        let subject = RecipientSetSubject::from_inner(recipient_set.clone())?;
        let mut requests = Vec::new();
        self.evaluate_artifact_recipient_set(&subject, &self_trust, &mut requests)?;
        if requests.is_empty() {
            Ok(TrustDecision::Trusted(()))
        } else {
            Ok(TrustDecision::ReviewRequired(requests))
        }
    }

    pub(crate) fn evaluate_new_kv_output(
        &self,
        sid: uuid::Uuid,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
    ) -> Result<TrustDecision> {
        self.enforce_store_owner(key_ctx)?;
        self.enforce_mutation_key_current(key_ctx)?;
        let self_trust = build_self_trust(key_ctx)?;
        let output = RecipientSetSubject::from_output_recipients(sid, recipients)?;
        let mut requests = Vec::new();
        self.evaluate_kv_output_recipients(&output, recipients, &self_trust, &mut requests)?;
        if requests.is_empty() {
            Ok(TrustDecision::Trusted(()))
        } else {
            Ok(TrustDecision::ReviewRequired(requests))
        }
    }

    /// Evaluate an exact output member set.
    pub(crate) fn preflight_output_recipient_keys(
        &self,
        recipients: &[PublicKey],
        self_trust: &SelfTrustSet,
    ) -> Result<TrustDecision> {
        self.enforce_output_public_key_set_current(recipients)?;
        let mut requests = Vec::new();
        self.evaluate_recipient_public_keys(recipients, self_trust, &mut requests)?;
        if requests.is_empty() {
            Ok(TrustDecision::Trusted(()))
        } else {
            Ok(TrustDecision::ReviewRequired(requests))
        }
    }

    fn evaluate_read_artifact(
        &self,
        proof: &SignatureVerificationProof,
        subject: &RecipientSetSubject,
        key_ctx: &KeyContext,
        exceptions: &ReadTrustExceptions,
    ) -> Result<Vec<TrustReviewRequest>> {
        self.enforce_store_owner(key_ctx)?;
        let self_trust = build_self_trust(key_ctx)?;
        let mut requests = self.evaluate_signer_with_exceptions(proof, &self_trust, exceptions)?;
        let _unresolved_recipient_kids =
            self.evaluate_recipient_keys(subject, &self_trust, &mut requests)?;
        if exceptions.known_key_review == KnownKeyReview::Skipped {
            requests.retain(|request| request.kind != TrustReviewKind::KnownKey);
        }
        Ok(requests)
    }

    fn kv_mutation_requests(
        &self,
        artifact: &VerifiedKvEncArtifact,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
    ) -> Result<Vec<TrustReviewRequest>> {
        self.enforce_store_owner(key_ctx)?;
        self.enforce_mutation_key_current(key_ctx)?;
        let self_trust = build_self_trust(key_ctx)?;
        let input = artifact.recipient_set_subject()?;
        let output = RecipientSetSubject::from_kv_mutation(artifact, recipients)?;
        let mut requests = self.evaluate_signer(artifact.inner().proof(), &self_trust)?;
        self.enforce_artifact_recipients_current(&input)?;
        self.evaluate_kv_output_recipients(&output, recipients, &self_trust, &mut requests)?;
        Ok(requests)
    }

    fn rewrap_requests(
        &self,
        input_evaluator: &TrustPolicyEvaluator,
        proof: &SignatureVerificationProof,
        input: &RecipientSetSubject,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
        exceptions: &ReadTrustExceptions,
    ) -> Result<Vec<TrustReviewRequest>> {
        let mut requests =
            input_evaluator.evaluate_read_artifact(proof, input, key_ctx, exceptions)?;
        self.enforce_store_owner(key_ctx)?;
        self.enforce_mutation_key_current(key_ctx)?;
        let self_trust = build_self_trust(key_ctx)?;
        let output = RecipientSetSubject::from_output_recipients(input.sid(), recipients)?;
        self.evaluate_kv_output_recipients(&output, recipients, &self_trust, &mut requests)?;
        Ok(requests)
    }

    pub(crate) fn preflight_rewrap_output(
        &self,
        input: &RecipientSetSubject,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
    ) -> Result<Vec<TrustReviewRequest>> {
        self.enforce_store_owner(key_ctx)?;
        self.enforce_mutation_key_current(key_ctx)?;
        let self_trust = build_self_trust(key_ctx)?;
        let output = RecipientSetSubject::from_output_recipients(input.sid(), recipients)?;
        let mut requests = Vec::new();
        self.evaluate_kv_output_recipients(&output, recipients, &self_trust, &mut requests)?;
        Ok(requests)
    }

    fn review_read_artifact(
        &self,
        proof: &SignatureVerificationProof,
        subject: &RecipientSetSubject,
        key_ctx: &KeyContext,
        known_key_review: KnownKeyReview,
        allow_non_member_review: bool,
    ) -> Result<ReadTrustReview> {
        self.enforce_store_owner(key_ctx)?;
        let self_trust = build_self_trust(key_ctx)?;
        let (mut requests, non_member_signer) = match self.evaluate_signer(proof, &self_trust) {
            Ok(requests) => (requests, None),
            Err(error)
                if allow_non_member_review
                    && error.kind() == ErrorKind::Verify
                    && error.rule() == Some("E_TRUST_NON_MEMBER") =>
            {
                (Vec::new(), Some(non_member_review_request(proof, subject)?))
            }
            Err(error) => return Err(error),
        };
        let mut signer_request_count = requests.len();
        let (unresolved_recipient_kids, recipient_error) =
            match self.evaluate_recipient_keys(subject, &self_trust, &mut requests) {
                Ok(kids) => (kids, None),
                Err(error) => (Vec::new(), Some(error)),
            };
        if known_key_review == KnownKeyReview::Skipped {
            requests.retain(|request| request.kind != TrustReviewKind::KnownKey);
            signer_request_count = 0;
        }
        Ok(ReadTrustReview {
            requests,
            signer_request_count,
            non_member_signer,
            unresolved_recipient_kids,
            recipient_error,
        })
    }

    fn evaluate_signer_with_exceptions(
        &self,
        proof: &SignatureVerificationProof,
        self_trust: &SelfTrustSet,
        exceptions: &ReadTrustExceptions,
    ) -> Result<Vec<TrustReviewRequest>> {
        match self.evaluate_signer(proof, self_trust) {
            Ok(requests) => Ok(requests),
            // The kind is checked alongside the rule because coded operation
            // errors carry rules too. Matching on the rule alone would let an
            // unrelated failure that happens to share it reach the policy and
            // accept a signer the review never saw.
            Err(error)
                if error.kind() == ErrorKind::Verify
                    && error.rule() == Some("E_TRUST_NON_MEMBER") =>
            {
                accept_reviewed_non_member(proof, exceptions, error)
            }
            Err(error) => Err(error),
        }
    }

    fn enforce_store_owner(&self, key_ctx: &KeyContext) -> Result<()> {
        let Some(store) = self.store.as_ref() else {
            return Ok(());
        };
        let owner_handle = &store.inner().document().protected.owner_handle;
        if owner_handle == key_ctx.member_handle().as_str() {
            return Ok(());
        }
        Err(Error::build_invalid_argument_error(format!(
            "Trust store owner_handle '{}' does not match key context member_handle '{}'",
            owner_handle,
            key_ctx.member_handle()
        )))
    }

    fn enforce_mutation_key_current(&self, key_ctx: &KeyContext) -> Result<()> {
        let Some(current) = self.members.members_by_kid.get(key_ctx.kid().as_str()) else {
            return Err(build_inactive_mutation_key_error(key_ctx));
        };
        if current.protected.subject_handle == key_ctx.member_handle().as_str()
            && key_ctx
                .inner()
                .local_key_identity()
                .matches_public_key(current)?
        {
            return Ok(());
        }
        Err(Error::build_verification_error(
            "E_TRUST_ACTIVE_MEMBER_MISMATCH".to_string(),
            format!(
                "Mutation key '{}' does not match current member '{}'",
                key_ctx.kid(),
                key_ctx.member_handle()
            ),
        ))
    }

    fn evaluate_signer(
        &self,
        proof: &SignatureVerificationProof,
        self_trust: &SelfTrustSet,
    ) -> Result<Vec<TrustReviewRequest>> {
        let public_key = proof
            .signer_public_key
            .as_ref()
            .ok_or_else(build_missing_signer_public_key_error)?;
        let identity = TrustIdentity::from_public_key(public_key)?;
        let judgment = judge_signer_trust(
            &identity,
            &self.members.active_members(),
            &KnownKeyCache::new(self.known_keys()),
            self_trust,
        )?;
        resolve_signer_judgment(judgment, public_key)
    }

    fn evaluate_recipient_keys(
        &self,
        subject: &RecipientSetSubject,
        self_trust: &SelfTrustSet,
        requests: &mut Vec<TrustReviewRequest>,
    ) -> Result<Vec<Kid>> {
        enforce_recipient_handle_consistency(subject, &self.members.members_by_kid)?;
        let mut public_keys = Vec::new();
        let mut unresolved = BTreeSet::new();
        for kid in &subject.recipient_kids {
            match self.members.members_by_kid.get(kid.as_str()) {
                Some(public_key) => public_keys.push(public_key.clone()),
                None => {
                    unresolved.insert(kid.clone());
                }
            }
        }
        self.evaluate_recipient_public_keys(&public_keys, self_trust, requests)?;
        Ok(unresolved.into_iter().collect())
    }

    fn evaluate_output_recipient_keys(
        &self,
        recipients: &RecipientKeys,
        self_trust: &SelfTrustSet,
        requests: &mut Vec<TrustReviewRequest>,
    ) -> Result<()> {
        let public_keys = recipients
            .keys()
            .iter()
            .map(|key| {
                self.enforce_output_recipient_current(key.document())?;
                Ok(key.document().clone())
            })
            .collect::<Result<Vec<_>>>()?;
        self.evaluate_recipient_public_keys(&public_keys, self_trust, requests)
    }

    fn evaluate_kv_output_recipients(
        &self,
        output: &RecipientSetSubject,
        recipients: &RecipientKeys,
        self_trust: &SelfTrustSet,
        requests: &mut Vec<TrustReviewRequest>,
    ) -> Result<()> {
        self.enforce_output_recipient_set_current(recipients)?;
        self.evaluate_output_recipient_keys(recipients, self_trust, requests)?;
        self.evaluate_artifact_recipient_set(output, self_trust, requests)
    }

    fn enforce_output_recipient_set_current(&self, recipients: &RecipientKeys) -> Result<()> {
        self.enforce_output_kid_set_current(
            recipients
                .keys()
                .iter()
                .map(|key| key.document().protected.kid.as_str()),
            recipients.keys().len(),
        )
    }

    fn evaluate_recipient_public_keys(
        &self,
        public_keys: &[PublicKey],
        self_trust: &SelfTrustSet,
        requests: &mut Vec<TrustReviewRequest>,
    ) -> Result<()> {
        let identities = public_keys
            .iter()
            .map(TrustIdentity::from_public_key)
            .collect::<Result<Vec<_>>>()?;
        let cache = KnownKeyCache::new(self.known_keys());
        cache.enforce_recipient_integrity(&identities)?;
        let pending = judge_recipients_trust(&identities, &cache, self_trust)?;
        for identity in pending {
            let public_key = public_keys
                .iter()
                .find(|key| key.protected.kid == identity.kid())
                .ok_or_else(|| Error::build_invalid_operation_error("Reviewed key disappeared"))?;
            push_known_key_review_request(requests, public_key)?;
        }
        Ok(())
    }

    fn enforce_output_public_key_set_current(&self, recipients: &[PublicKey]) -> Result<()> {
        self.enforce_output_kid_set_current(
            recipients.iter().map(|key| key.protected.kid.as_str()),
            recipients.len(),
        )?;
        for recipient in recipients {
            self.enforce_output_recipient_current(recipient)?;
        }
        Ok(())
    }

    /// Refuse output recipients that are not exactly the current member keys.
    ///
    /// The comparison bites where the member snapshot was read from the
    /// workspace, which is the rewrap path. On the KV commit path it cannot:
    /// the snapshot there is built from the very recipient keys being checked,
    /// so both sides come from one source and the answer is always yes. What
    /// guards that path is the input side instead, where the artifact's own
    /// recipients are checked against the members, together with the review
    /// snapshot being compared again before the replacement is published.
    fn enforce_output_kid_set_current<'a>(
        &self,
        output_kids: impl IntoIterator<Item = &'a str>,
        output_count: usize,
    ) -> Result<()> {
        let output_kids = output_kids.into_iter().collect::<BTreeSet<_>>();
        let matches_current = matches!(
            self.members
                .active_members()
                .judge_kid_set_match(output_kids.iter().copied()),
            KidSetMatch::Exact
        );
        if !matches_current || output_kids.len() != output_count {
            return Err(Error::build_verification_error(
                "E_TRUST_REJECTED".to_string(),
                "Output recipients must match all current members/active keys".to_string(),
            ));
        }
        Ok(())
    }

    fn enforce_artifact_recipients_current(&self, subject: &RecipientSetSubject) -> Result<()> {
        enforce_recipient_handle_consistency(subject, &self.members.members_by_kid)?;
        match find_inactive_recipient_kid(&subject.inner, &self.members.members_by_kid) {
            Some(kid) => Err(build_inactive_recipient_error(kid)),
            None => Ok(()),
        }
    }

    fn enforce_output_recipient_current(&self, recipient: &PublicKey) -> Result<()> {
        let kid = &recipient.protected.kid;
        match self
            .members
            .active_members()
            .judge_public_key_match(recipient)
        {
            CurrentKeyMatch::Matched => Ok(()),
            CurrentKeyMatch::Missing => Err(build_inactive_recipient_error(kid)),
            CurrentKeyMatch::DocumentMismatch => Err(Error::build_verification_error(
                "E_ARTIFACT_RECIPIENT_KEY_MISMATCH".to_string(),
                format!("Output recipient kid '{}' differs from members/active", kid),
            )),
        }
    }

    fn evaluate_artifact_recipient_set(
        &self,
        subject: &RecipientSetSubject,
        self_trust: &SelfTrustSet,
        requests: &mut Vec<TrustReviewRequest>,
    ) -> Result<()> {
        if is_self_only_recipient_set(&subject.inner, &self.members.members_by_kid, self_trust)? {
            return Ok(());
        }
        let (kind, approved) = match judge_recipient_set(self.recipient_sets(), &subject.inner) {
            RecipientSetJudgment::Accepted => return Ok(()),
            RecipientSetJudgment::Missing => (TrustReviewKind::RecipientSet, None),
            RecipientSetJudgment::Changed { approved } => {
                (TrustReviewKind::ChangedRecipientSet, Some(approved))
            }
        };
        requests.push(recipient_review_request(
            kind,
            &subject.inner,
            approved.as_ref(),
        )?);
        Ok(())
    }

    fn recipient_sets(&self) -> &[RecipientSetRecord] {
        self.store
            .as_ref()
            .map(|store| store.inner().document().protected.recipient_sets.as_slice())
            .unwrap_or(&[])
    }
}

/// Turn one signer judgment into the review it asks for or the error it states.
fn resolve_signer_judgment(
    judgment: TrustJudgment,
    public_key: &PublicKey,
) -> Result<Vec<TrustReviewRequest>> {
    match enforce_signer_judgment(judgment)? {
        SignerAcceptance::Trusted => Ok(Vec::new()),
        SignerAcceptance::NeedsApproval { .. } => Ok(vec![known_key_review_request(public_key)?]),
    }
}

/// Accept a signer the trust rules rejected as a non-member, but only when the
/// policy names the exact identity a review already accepted.
fn accept_reviewed_non_member(
    proof: &SignatureVerificationProof,
    exceptions: &ReadTrustExceptions,
    error: Error,
) -> Result<Vec<TrustReviewRequest>> {
    let Some(public_key) = proof.signer_public_key.as_ref() else {
        return Err(error);
    };
    let identity = TrustIdentity::from_public_key(public_key)?;
    let accepted = exceptions
        .accepted_non_member
        .as_ref()
        .is_some_and(|(handle, kid)| {
            handle.as_str() == identity.member_handle() && kid.as_str() == identity.kid()
        });
    if accepted {
        Ok(Vec::new())
    } else {
        Err(error)
    }
}

fn build_missing_signer_public_key_error() -> Error {
    Error::build_verification_error(
        "E_SIGNER_PUB_MISSING".to_string(),
        "Required signer_pub is missing from verified proof".to_string(),
    )
}

fn build_self_trust(key_ctx: &KeyContext) -> Result<SelfTrustSet> {
    let sig_x = [key_ctx.inner().self_signature_public_key_x()];
    match key_ctx.inner().local_keystore_access() {
        Some(access) => SelfTrustSet::try_new_with_keystore(
            key_ctx.member_handle().clone(),
            sig_x,
            access.clone(),
        ),
        None => SelfTrustSet::try_new(key_ctx.member_handle().clone(), sig_x),
    }
}

fn known_key_review_request(public_key: &PublicKey) -> Result<TrustReviewRequest> {
    let candidate = KnownKeyReviewCandidate::from_public_key(public_key)?;
    Ok(TrustReviewRequest {
        kind: TrustReviewKind::KnownKey,
        subject_handle: Some(candidate.subject_handle.clone()),
        kid: Some(candidate.kid.clone()),
        known_key_candidate: Some(candidate),
        sid: None,
        recipient_kids: Vec::new(),
        recipient_handle_hints: Vec::new(),
        approved_recipient_set: None,
    })
}

fn non_member_review_request(
    proof: &SignatureVerificationProof,
    subject: &RecipientSetSubject,
) -> Result<NonMemberSignerReview> {
    let public_key = proof
        .signer_public_key
        .as_ref()
        .ok_or_else(build_missing_signer_public_key_error)?;
    let candidate = KnownKeyReviewCandidate::from_public_key(public_key)?;
    let recipient_handles = subject
        .inner
        .recipient_handle_hints()
        .iter()
        .map(|hint| MemberHandle::new(hint.recipient_handle.clone()))
        .collect::<Result<Vec<_>>>()?;
    Ok(NonMemberSignerReview {
        candidate,
        recipient_handles,
    })
}

fn push_known_key_review_request(
    requests: &mut Vec<TrustReviewRequest>,
    public_key: &PublicKey,
) -> Result<()> {
    let candidate = KnownKeyReviewCandidate::from_public_key(public_key)?;
    let duplicate = requests.iter().any(|request| {
        request.kind == TrustReviewKind::KnownKey
            && request.subject_handle() == Some(&candidate.subject_handle)
            && request.kid() == Some(&candidate.kid)
    });
    if !duplicate {
        requests.push(TrustReviewRequest {
            kind: TrustReviewKind::KnownKey,
            subject_handle: Some(candidate.subject_handle.clone()),
            kid: Some(candidate.kid.clone()),
            known_key_candidate: Some(candidate),
            sid: None,
            recipient_kids: Vec::new(),
            recipient_handle_hints: Vec::new(),
            approved_recipient_set: None,
        });
    }
    Ok(())
}

fn enforce_recipient_handle_consistency(
    subject: &RecipientSetSubject,
    members_by_kid: &BTreeMap<String, PublicKey>,
) -> Result<()> {
    let Some(mismatch) = find_recipient_handle_mismatch(&subject.inner, members_by_kid) else {
        return Ok(());
    };
    Err(Error::build_verification_error(
        "E_RECIPIENT_SET_HANDLE_MISMATCH".to_string(),
        format!(
            "Artifact recipient label differs from members/active.\n\
             Kid: {}\n\
             Artifact label: {}\n\
             Active label: {}",
            mismatch.kid, mismatch.artifact_recipient_handle, mismatch.active_member_handle
        ),
    ))
}

fn build_inactive_recipient_error(kid: &str) -> Error {
    Error::build_verification_error(
        "E_ARTIFACT_RECIPIENT_NOT_ACTIVE".to_string(),
        format!(
            "Artifact recipient kid is not active.\n\
             Kid: {}\n\
             The artifact must be rewrapped before writing.",
            kid
        ),
    )
}

fn build_inactive_mutation_key_error(key_ctx: &KeyContext) -> Error {
    Error::build_verification_error(
        "E_TRUST_NON_MEMBER".to_string(),
        format!(
            "Mutation key is not a current active member.\nmember: {}\nkid: {}",
            key_ctx.member_handle(),
            key_ctx.kid()
        ),
    )
}

impl RecipientSetSubject {
    pub(crate) fn from_verified_file(document: &VerifiedFileEncDocument) -> Result<Self> {
        file_recipient_evidence(document.document())
            .and_then(|evidence| Self::from_inner(evidence.recipient_set))
    }

    pub(crate) fn from_verified_kv(document: &VerifiedKvEncDocument) -> Result<Self> {
        kv_recipient_evidence(document.document())
            .and_then(|evidence| Self::from_inner(evidence.recipient_set))
    }

    fn from_kv_mutation(
        artifact: &VerifiedKvEncArtifact,
        recipients: &RecipientKeys,
    ) -> Result<Self> {
        let sid = artifact.inner().document().head().sid;
        Self::from_output_recipients(sid, recipients)
    }

    pub(crate) fn from_output_recipients(
        sid: uuid::Uuid,
        recipients: &RecipientKeys,
    ) -> Result<Self> {
        let public_keys = recipients
            .keys()
            .iter()
            .map(|key| key.document().clone())
            .collect::<Vec<_>>();
        ArtifactRecipientSet::from_public_keys(sid, &public_keys).and_then(Self::from_inner)
    }

    /// Return the artifact recipient-set ID.
    pub fn sid(&self) -> uuid::Uuid {
        self.inner.sid()
    }

    /// Return canonical recipient key IDs.
    pub fn recipient_kids(&self) -> &[Kid] {
        &self.recipient_kids
    }

    fn from_inner(inner: ArtifactRecipientSet) -> Result<Self> {
        let recipient_kids = inner
            .recipient_kids()
            .iter()
            .cloned()
            .map(Kid::new)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            inner,
            recipient_kids,
        })
    }
}

impl VerifiedLocalTrustStoreLoadResult {
    pub(crate) fn store(&self) -> &VerifiedLocalTrustStore {
        &self.store
    }

    pub(crate) fn protected(&self) -> &TrustStoreProtected {
        &self.store.inner().document().protected
    }

    /// The verified content and the key it was signed with, as stored state.
    ///
    /// Verification resolves the signer key before it accepts anything, so a
    /// result that came back verified always names one.
    pub(crate) fn into_state(self) -> TrustStoreState {
        let (document, _) = self.store.inner.into_inner();
        TrustStoreState {
            protected: document.protected,
            signer_kid: self.signer_kid,
        }
    }

    /// Consume the result and return the verified local trust store facade.
    pub fn into_store(self) -> VerifiedLocalTrustStore {
        self.store
    }
}

impl VerifiedLocalTrustStore {
    fn from_inner(inner: VerifiedTrustStore) -> Self {
        Self { inner }
    }

    fn inner(&self) -> &VerifiedTrustStore {
        &self.inner
    }

    fn protected(&self) -> &TrustStoreProtected {
        &self.inner.document().protected
    }
}

impl TrustReviewRequest {
    /// Return the review request category.
    pub fn kind(&self) -> TrustReviewKind {
        self.kind
    }

    /// Return the subject handle for known-key review requests.
    pub fn subject_handle(&self) -> Option<&MemberHandle> {
        self.subject_handle.as_ref()
    }

    /// Return the key ID for known-key review requests.
    pub fn kid(&self) -> Option<&Kid> {
        self.kid.as_ref()
    }

    /// Return the verified candidate for a known-key review request.
    pub fn known_key_candidate(&self) -> Option<&KnownKeyReviewCandidate> {
        self.known_key_candidate.as_ref()
    }

    /// Return the artifact recipient-set ID for recipient-set review requests.
    pub fn sid(&self) -> Option<uuid::Uuid> {
        self.sid
    }

    /// Return the recipient key IDs for recipient-set review requests.
    pub fn recipient_kids(&self) -> &[Kid] {
        &self.recipient_kids
    }

    /// Return display-only recipient identity hints for recipient-set review.
    pub fn recipient_handle_hints(&self) -> &[TrustRecipientHandleHint] {
        &self.recipient_handle_hints
    }

    /// Return the recipient set the last local approval stored for this artifact.
    ///
    /// Only a changed recipient-set review has one, and it is what the current
    /// set is shown against so the operator sees which members the change adds
    /// and removes.
    pub fn approved_recipient_set(&self) -> Option<&ArtifactRecipientSetSnapshot> {
        self.approved_recipient_set.as_ref()
    }
}

impl ReadTrustReview {
    pub(crate) fn requests(&self) -> &[TrustReviewRequest] {
        &self.requests
    }

    pub(crate) fn non_member_signer(&self) -> Option<&NonMemberSignerReview> {
        self.non_member_signer.as_ref()
    }

    pub(crate) fn first_request_is_signer(&self) -> bool {
        self.signer_request_count > 0
    }

    pub(crate) fn unresolved_recipient_kids(&self) -> &[Kid] {
        &self.unresolved_recipient_kids
    }

    pub(crate) fn into_recipient_requests(self) -> Result<Vec<TrustReviewRequest>> {
        match self.recipient_error {
            Some(error) => Err(error),
            None => Ok(self.requests),
        }
    }
}

impl NonMemberSignerReview {
    pub(crate) fn candidate(&self) -> &KnownKeyReviewCandidate {
        &self.candidate
    }

    pub(crate) fn recipient_handles(&self) -> &[MemberHandle] {
        &self.recipient_handles
    }
}

impl TrustRecipientHandleHint {
    /// Return the recipient key ID.
    pub fn kid(&self) -> &Kid {
        &self.kid
    }

    /// Return the recipient member handle.
    pub fn recipient_handle(&self) -> &MemberHandle {
        &self.recipient_handle
    }

    #[cfg(test)]
    pub(crate) fn for_test(kid: impl Into<String>, recipient_handle: impl Into<String>) -> Self {
        Self {
            kid: Kid::new(kid).expect("canonical test kid"),
            recipient_handle: MemberHandle::new(recipient_handle)
                .expect("valid test recipient handle"),
        }
    }

    fn from_model(hint: &RecipientHandleHint) -> Result<Self> {
        Ok(Self {
            kid: Kid::new(hint.kid.clone())?,
            recipient_handle: MemberHandle::new(hint.recipient_handle.clone())?,
        })
    }

    fn into_model(self) -> RecipientHandleHint {
        RecipientHandleHint {
            kid: self.kid.into_string(),
            recipient_handle: self.recipient_handle.into_string(),
        }
    }
}

impl KnownKeyReviewCandidate {
    pub(crate) fn from_public_key(public_key: &PublicKey) -> Result<Self> {
        Ok(Self {
            public_key: public_key.clone(),
            subject_handle: MemberHandle::new(public_key.protected.subject_handle.clone())?,
            kid: Kid::new(public_key.protected.kid.clone())?,
            fingerprint: crate::io::ssh::protocol::build_sha256_fingerprint(
                &public_key.protected.attestation.pub_,
            )
            .ok(),
        })
    }

    pub(crate) fn from_verified_signing_public_key(
        public_key: &VerifiedSigningPublicKey,
    ) -> Result<Self> {
        Self::from_public_key(public_key.document())
    }

    /// Return the verified subject handle.
    pub fn subject_handle(&self) -> &MemberHandle {
        &self.subject_handle
    }

    /// Return the verified canonical key ID.
    pub fn kid(&self) -> &Kid {
        &self.kid
    }

    /// Return the SSH attestor fingerprint when it can be computed.
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    /// Return the SSH attestor public key covered by the verified statement.
    pub fn ssh_attestor_public_key(&self) -> &str {
        &self.public_key.protected.attestation.pub_
    }

    /// Return whether the verified statement carries a GitHub binding claim.
    pub fn has_github_binding(&self) -> bool {
        self.public_key
            .protected
            .binding_claims
            .as_ref()
            .and_then(|claims| claims.github_account.as_ref())
            .is_some()
    }

    pub(crate) fn github_account_id(&self) -> Option<u64> {
        self.public_key
            .protected
            .binding_claims
            .as_ref()
            .and_then(|claims| claims.github_account.as_ref())
            .map(|account| account.id)
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        subject_handle: impl Into<String>,
        kid: impl Into<String>,
        attestor: impl Into<String>,
    ) -> Self {
        Self::for_test_with_github_binding(subject_handle, kid, attestor, false)
    }

    #[cfg(any(test, feature = "cli-test-support"))]
    pub(crate) fn for_test_with_github_binding(
        subject_handle: impl Into<String>,
        kid: impl Into<String>,
        attestor: impl Into<String>,
        github_binding_configured: bool,
    ) -> Self {
        Self::for_test_with_github_account_id(
            subject_handle,
            kid,
            attestor,
            github_binding_configured.then_some(42),
            None,
        )
    }

    #[cfg(any(test, feature = "cli-test-support"))]
    pub(crate) fn for_test_with_github_account_id(
        subject_handle: impl Into<String>,
        kid: impl Into<String>,
        attestor: impl Into<String>,
        github_account_id: Option<u64>,
        fingerprint: Option<String>,
    ) -> Self {
        use crate::model::public_key::{
            Attestation, BindingClaims, GithubAccount, IdentityKeys, JwkOkpPublicKey,
            PublicKeyProtected,
        };
        let subject_handle = MemberHandle::new(subject_handle).expect("valid test member handle");
        let kid = Kid::new(kid).expect("canonical test kid");
        let test_jwk = |curve: &str| JwkOkpPublicKey {
            kty: "OKP".to_string(),
            crv: curve.to_string(),
            x: "test-only".to_string(),
        };
        let public_key = PublicKey {
            protected: PublicKeyProtected {
                format: "kapsaro:format:public-key@1".to_string(),
                subject_handle: subject_handle.to_string(),
                kid: kid.to_string(),
                keys: IdentityKeys {
                    kem: test_jwk("X25519"),
                    sig: test_jwk("Ed25519"),
                },
                binding_claims: github_account_id.map(|id| BindingClaims {
                    github_account: Some(GithubAccount {
                        id,
                        login: "test-account".to_string(),
                    }),
                }),
                attestation: Attestation {
                    method: "ssh-sign".to_string(),
                    pub_: attestor.into(),
                    sig: "test-only".to_string(),
                },
                expires_at: "2099-01-01T00:00:00Z".to_string(),
                created_at: None,
            },
            signature: "test-only".to_string(),
        };
        Self {
            public_key,
            subject_handle,
            kid,
            fingerprint,
        }
    }
}

impl KnownKeyApprovalEvidence {
    /// Build an approval with no recorded external evidence.
    pub fn none() -> Self {
        Self {
            verified_github: None,
            ssh_attestor_public_key: None,
        }
    }

    /// Record GitHub evidence produced by candidate verification.
    pub fn with_verified_github_account(
        mut self,
        evidence: crate::service::online::VerifiedGitHubEvidence,
    ) -> Self {
        self.verified_github = Some(evidence);
        self
    }

    /// Record the SSH attestor public key presented during review.
    pub fn with_ssh_attestor_public_key(mut self, key: impl Into<String>) -> Self {
        self.ssh_attestor_public_key = Some(key.into());
        self
    }

    fn validate_for(&self, candidate: &KnownKeyReviewCandidate) -> Result<()> {
        if candidate.has_github_binding()
            && self
                .verified_github
                .as_ref()
                .is_none_or(|evidence| !evidence.matches_candidate(candidate))
        {
            return Err(Error::build_verification_error(
                "E_TRUST_APPROVAL_EVIDENCE_MISMATCH".to_string(),
                "Known-key approval requires GitHub evidence verified for this candidate"
                    .to_string(),
            ));
        }
        if self
            .verified_github
            .as_ref()
            .is_some_and(|evidence| !evidence.matches_candidate(candidate))
        {
            return Err(Error::build_verification_error(
                "E_TRUST_APPROVAL_EVIDENCE_MISMATCH".to_string(),
                "GitHub evidence belongs to a different known-key candidate".to_string(),
            ));
        }
        if self
            .ssh_attestor_public_key
            .as_deref()
            .is_some_and(|key| key != candidate.ssh_attestor_public_key())
        {
            return Err(Error::build_verification_error(
                "E_TRUST_APPROVAL_EVIDENCE_MISMATCH".to_string(),
                "SSH attestor evidence differs from the reviewed candidate".to_string(),
            ));
        }
        Ok(())
    }

    fn into_model(self) -> Option<KnownKeyEvidence> {
        let github_account = self.verified_github.map(|evidence| {
            let account = evidence.account();
            KnownKeyGithubAccount {
                id: account.id(),
                login: Some(account.login().to_string()),
            }
        });
        if github_account.is_none() && self.ssh_attestor_public_key.is_none() {
            return None;
        }
        Some(KnownKeyEvidence {
            github_account,
            ssh_attestor_pub: self.ssh_attestor_public_key,
        })
    }
}

impl TrustApprovalOutcome {
    /// Return how many approvals changed the stored trust state.
    pub fn applied(&self) -> usize {
        self.applied
    }

    /// Return permission warnings observed while applying approvals.
    pub fn warnings(&self) -> &DiagnosticBatch {
        &self.warnings
    }

    /// Consume an outcome so first-party orchestration can route its warnings.
    pub(crate) fn into_parts(self) -> (usize, DiagnosticBatch) {
        (self.applied, self.warnings)
    }
}

impl TrustApproval {
    /// Build a known-key approval.
    pub fn known_key(
        candidate: &KnownKeyReviewCandidate,
        evidence: KnownKeyApprovalEvidence,
    ) -> Result<Self> {
        evidence.validate_for(candidate)?;
        Ok(Self {
            kind: TrustApprovalKind::KnownKey(Box::new(KnownKeyApproval {
                candidate: candidate.clone(),
                evidence,
            })),
        })
    }

    /// Build a recipient-set approval.
    pub fn recipient_set(
        sid: uuid::Uuid,
        recipient_kids: Vec<Kid>,
        recipient_handle_hints: Vec<TrustRecipientHandleHint>,
    ) -> Result<Self> {
        if recipient_handle_hints.len() != recipient_kids.len() {
            return Err(Error::build_invalid_argument_error(
                "recipient handle hints must identify every recipient kid".to_string(),
            ));
        }
        ArtifactRecipientSet::from_parts(
            sid,
            recipient_kids.iter().map(ToString::to_string).collect(),
            recipient_handle_hints
                .iter()
                .cloned()
                .map(TrustRecipientHandleHint::into_model)
                .collect(),
        )?;
        Ok(Self {
            kind: TrustApprovalKind::RecipientSet(RecipientSetApproval {
                sid,
                recipient_kids,
                recipient_handle_hints,
            }),
        })
    }

    pub(crate) fn recipient_set_from_artifact(
        recipient_set: &ArtifactRecipientSet,
    ) -> Result<Self> {
        let request = recipient_review_request(TrustReviewKind::RecipientSet, recipient_set, None)?;
        Self::recipient_set(
            request.sid().expect("recipient review carries sid"),
            request.recipient_kids().to_vec(),
            request.recipient_handle_hints().to_vec(),
        )
    }

    #[cfg(test)]
    pub(crate) fn known_key_for_test(
        subject_handle: impl Into<String>,
        kid: impl Into<String>,
    ) -> Self {
        let candidate =
            KnownKeyReviewCandidate::for_test(subject_handle, kid, "ssh-ed25519 test-only");
        Self::known_key(&candidate, KnownKeyApprovalEvidence::none())
            .expect("test candidate without binding accepts empty evidence")
    }

    #[cfg(test)]
    pub(crate) fn known_key_with_evidence_for_test(
        subject_handle: impl Into<String>,
        kid: impl Into<String>,
        attestor: Option<String>,
        github: Option<(u64, String, String, i64)>,
    ) -> Self {
        let github_account_id = github.as_ref().map(|(id, ..)| *id);
        let candidate = KnownKeyReviewCandidate::for_test_with_github_account_id(
            subject_handle,
            kid,
            attestor
                .clone()
                .unwrap_or_else(|| "ssh-ed25519 test-only".to_string()),
            github_account_id,
            None,
        );
        let mut evidence = KnownKeyApprovalEvidence::none();
        if let Some(attestor) = attestor {
            evidence = evidence.with_ssh_attestor_public_key(attestor);
        }
        if let Some((id, login, fingerprint, matched_key_id)) = github {
            evidence = evidence.with_verified_github_account(
                crate::service::online::VerifiedGitHubEvidence::for_test(
                    &candidate,
                    id,
                    login,
                    fingerprint,
                    matched_key_id,
                ),
            );
        }
        Self::known_key(&candidate, evidence).expect("valid test known-key evidence")
    }

    #[cfg(test)]
    pub(crate) fn recipient_set_for_test(sid: uuid::Uuid, recipient_kids: Vec<String>) -> Self {
        Self {
            kind: TrustApprovalKind::RecipientSet(RecipientSetApproval {
                sid,
                recipient_kids: recipient_kids
                    .into_iter()
                    .map(|kid| Kid::new(kid).expect("canonical test kid"))
                    .collect(),
                recipient_handle_hints: Vec::new(),
            }),
        }
    }
}

impl KnownKeyApproval {
    fn into_known_key(self, approved_at: String) -> Result<KnownKey> {
        let identity = KnownKeyIdentity::try_new(
            self.candidate.subject_handle.to_string(),
            self.candidate.kid.to_string(),
        )?;
        Ok(KnownKey {
            kid: identity.kid().to_string(),
            subject_handle: identity.member_handle().to_string(),
            approved_at,
            approved_via: KnownKeyApprovalVia::ManualReview,
            evidence: self.evidence.into_model(),
            extra: BTreeMap::new(),
        })
    }
}

fn recipient_review_request(
    kind: TrustReviewKind,
    current: &ArtifactRecipientSet,
    approved: Option<&RecipientSetRecord>,
) -> Result<TrustReviewRequest> {
    Ok(TrustReviewRequest {
        kind,
        subject_handle: None,
        kid: None,
        known_key_candidate: None,
        sid: Some(current.sid()),
        recipient_kids: current
            .recipient_kids()
            .iter()
            .cloned()
            .map(Kid::new)
            .collect::<Result<Vec<_>>>()?,
        recipient_handle_hints: current
            .recipient_handle_hints()
            .iter()
            .map(TrustRecipientHandleHint::from_model)
            .collect::<Result<Vec<_>>>()?,
        approved_recipient_set: approved.map(ArtifactRecipientSetSnapshot::from_record),
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_trust_core_store_mutation_test.rs"]
mod service_trust_core_store_mutation_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_trust_core_read_test.rs"]
mod service_trust_core_read_test;
