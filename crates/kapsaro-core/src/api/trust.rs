// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Non-interactive local trust store facade.
//! Exposes trust evaluation and lock-coordinated local persistence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::feature::context::crypto::{build_signing_context, VerifiedSigningContext};
use crate::feature::trust::judgment::{
    build_active_members_by_kid, judge_recipients_trust, judge_signer_trust, ActiveMemberSnapshot,
    AdditionalKnownKeyCache, KnownKeyCache, SelfTrustSet, TrustIdentity, TrustJudgment,
};
use crate::feature::trust::known_keys::{
    add_known_key, judge_known_key, KnownKeyIdentity, KnownKeyJudgment,
};
use crate::feature::trust::recipient_sets::{
    file_recipient_evidence, find_recipient_handle_mismatch, is_self_only_recipient_set,
    judge_recipient_set, kv_recipient_evidence, upsert_recipient_set, ArtifactRecipientSet,
    RecipientSetJudgment,
};
use crate::feature::trust::signer_keys::document_signer_kid;
use crate::feature::trust::store_mutation::{
    TrustStoreMutation, TrustStoreMutationMode, TrustStoreMutationTarget, TrustStoreState,
};
use crate::feature::trust::transaction::{
    commit_trust_store_mutation, resolve_owner_keystore, verify_trust_store_with_owner_keys,
    ObservedTrustStore, TrustStoreCommitGate, TrustStorePreparation,
};
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
};
use crate::io::keystore::access::{build_local_keystore_capability_error, KeystoreAccess};
use crate::io::trust::paths::{get_trust_store_file_path, TRUST_DIR_NAME};
use crate::io::trust::store::{
    attach_trust_store_recovery, load_trust_store_with_shared_lock, TrustStoreSnapshot,
};
use crate::io::workspace::members::{load_active_member_files, load_active_member_files_at};
use crate::model::identity::Kid;
use crate::model::public_key::PublicKey;
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, RecipientHandleHint, RecipientSetRecord, TrustStoreProtected,
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
use crate::{Error, ErrorKind, Result};

use super::file::{FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact};
use super::key::{KeyContext, LocalKeyStore, MemberHandle, RecipientKeys};
use super::kv::{
    AuthorizedKvMutation, KvMutationOperation, KvReadOperation, TrustedKvEncArtifact,
    VerifiedKvEncArtifact,
};
use super::operation::OperationOptions;

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
#[derive(Debug, Clone)]
pub struct CurrentMemberSnapshot {
    members_by_kid: BTreeMap<String, PublicKey>,
}

pub(crate) struct CliReadTrustPolicy {
    pub(crate) skip_known_key_review: bool,
    pub(crate) accepted_non_member: Option<(String, String)>,
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
    subject_handle: Option<String>,
    kid: Option<String>,
    sid: Option<String>,
    recipient_kids: Vec<String>,
    recipient_handle_hints: Vec<TrustRecipientHandleHint>,
}

/// Display-only recipient identity captured for recipient-set review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRecipientHandleHint {
    kid: String,
    recipient_handle: String,
}

/// Review request category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustReviewKind {
    KnownKey,
    RecipientSet,
    ChangedRecipientSet,
}

/// Caller-approved trust update.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustApproval {
    kind: TrustApprovalKind,
}

#[derive(Debug, Clone, PartialEq)]
enum TrustApprovalKind {
    KnownKey(KnownKeyApproval),
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
    Surface(ReviewedTrustStore),
}

/// The content one caller reviewed, with the key it was verified against.
///
/// The commit accepts nothing but this content, so the signer it names is the
/// only key the write-back can need. A reviewed absence names none.
#[derive(Debug, Clone)]
struct ReviewedTrustStore {
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
            policy: ApprovalConflictPolicy::Surface(ReviewedTrustStore {
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
            policy: ApprovalConflictPolicy::Surface(ReviewedTrustStore {
                snapshot: TrustStoreSnapshot::Missing,
                signer_kid: None,
            }),
        }
    }
}

/// Caller-approved known-key trust update.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KnownKeyApproval {
    subject_handle: String,
    kid: String,
}

/// Caller-approved recipient-set trust update.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecipientSetApproval {
    sid: uuid::Uuid,
    recipient_kids: Vec<String>,
    recipient_handle_hints: Vec<TrustRecipientHandleHint>,
}

/// Capabilities one caller-approved trust update writes through.
struct ApprovalMutationContext<'a> {
    signing: VerifiedSigningContext<'a>,
    keystore: &'a KeystoreAccess,
    trust_dir: OpenDir,
    path: PathBuf,
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

    /// Create or reuse a restricted `<KAPSARO_HOME>` directory.
    pub fn create(base_dir: impl Into<PathBuf>, owner_handle: MemberHandle) -> Result<Self> {
        let base_dir =
            AnchoredDir::create(base_dir, DirectoryScope::LocalState, "local state root")?;
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
        self.read_verified_at(trust_dir, keystore, &path)
            .map_err(|error| attach_trust_store_recovery(&path, error))
    }

    /// Read the stored bytes and verify them against the owner's signer keys.
    ///
    /// Opening the keystore is a capability of its own and its failures name
    /// the keys directory, so those travel as they are: describing them against
    /// the trust store would send the operator to a file that is not what is
    /// wrong. They already name their own repair, which is what keeps them out
    /// of the reset offer wrapped around this.
    fn read_verified_at<D>(
        &self,
        trust_dir: &D,
        keystore: Option<&KeystoreAccess>,
        path: &Path,
    ) -> Result<Option<VerifiedLocalTrustStoreLoadResult>>
    where
        D: DirectoryFd + LockTargetDirectory,
    {
        let Some(loaded) = load_trust_store_with_shared_lock(&self.base_dir, trust_dir, path)?
        else {
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
    ) -> Result<()> {
        match conflict_handling.policy {
            ApprovalConflictPolicy::Merge => self.apply_approvals_merged(approvals, key_ctx),
            ApprovalConflictPolicy::Surface(reviewed) => {
                self.apply_approvals_reviewed(approvals, key_ctx, reviewed)
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
        approvals: Vec<TrustApproval>,
        key_ctx: &KeyContext,
    ) -> Result<()> {
        let context = self.build_mutation_context(key_ctx)?;
        let observed = self.observe(&context)?;
        commit_trust_store_mutation(
            &self.mutation_target(&context),
            observed.prepared(),
            TrustStoreCommitGate::LatestContent,
            |protected| self.apply_approvals_to(protected, approvals),
        )
        .map(|_| ())
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
        approvals: Vec<TrustApproval>,
        key_ctx: &KeyContext,
        reviewed: ReviewedTrustStore,
    ) -> Result<()> {
        let context = self.build_mutation_context(key_ctx)?;
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
        .map(|_| ())
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
            &context.trust_dir,
            &context.path,
            &self.owner_handle,
            context.keystore,
        )
        .map_err(|error| attach_trust_store_recovery(&context.path, error))
    }

    /// Resolve everything one approval writes through before any lock is taken.
    ///
    /// The trust directory is created here, so a caller that approves nothing
    /// still ends up with the directory the store will live in.
    fn build_mutation_context<'a>(
        &self,
        key_ctx: &'a KeyContext,
    ) -> Result<ApprovalMutationContext<'a>> {
        self.ensure_owner_key_context(key_ctx)?;
        let signing = build_signing_context(key_ctx.inner())?;
        let keystore = self.require_local_keystore(key_ctx)?;
        let trust_dir = ensure_child_dir_restricted_at(&self.base_dir, TRUST_DIR_NAME)?;
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
            trust_dir: &context.trust_dir,
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
    ) -> Result<TrustStoreMutation<()>> {
        let mut changed = false;
        for approval in approvals {
            changed |= self.apply_approval_update(protected, approval)?;
        }
        Ok(TrustStoreMutation { value: (), changed })
    }

    fn apply_approval_update(
        &self,
        protected: &mut TrustStoreProtected,
        approval: TrustApproval,
    ) -> Result<bool> {
        match approval.kind {
            TrustApprovalKind::KnownKey(key) => self.apply_known_key_approval(protected, key),
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
    let recipient_set =
        ArtifactRecipientSet::from_parts(approval.sid, approval.recipient_kids, hints)?;
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

    pub(crate) fn from_recipient_keys(recipients: &RecipientKeys) -> Result<Self> {
        let members = recipients
            .keys()
            .iter()
            .map(|key| key.document().clone())
            .collect::<Vec<_>>();
        build_active_members_by_kid(&members).map(|members_by_kid| Self { members_by_kid })
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

    /// Evaluate and bind a verified file artifact to its read key.
    pub fn evaluate_file<'a>(
        &self,
        artifact: &'a VerifiedFileEncArtifact,
        key_ctx: &'a KeyContext,
        operation: FileReadOperation,
        options: OperationOptions,
    ) -> Result<TrustDecision<TrustedFileEncArtifact<'a>>> {
        let FileReadOperation::Decrypt = operation;
        let subject = artifact.recipient_set_subject()?;
        let requests =
            self.evaluate_read_artifact(artifact.inner().proof(), &subject, key_ctx, None)?;
        if !requests.is_empty() {
            return Ok(TrustDecision::ReviewRequired(requests));
        }
        TrustedFileEncArtifact::from_authorized(artifact, key_ctx, options)
            .map(TrustDecision::Trusted)
    }

    /// Evaluate and bind a verified KV artifact to one read operation and key.
    pub fn evaluate_kv<'a>(
        &self,
        artifact: &'a VerifiedKvEncArtifact,
        key_ctx: &'a KeyContext,
        operation: KvReadOperation,
        options: OperationOptions,
    ) -> Result<TrustDecision<TrustedKvEncArtifact<'a>>> {
        let subject = artifact.recipient_set_subject()?;
        let requests =
            self.evaluate_read_artifact(artifact.inner().proof(), &subject, key_ctx, None)?;
        if !requests.is_empty() {
            return Ok(TrustDecision::ReviewRequired(requests));
        }
        TrustedKvEncArtifact::from_authorized(artifact, key_ctx, operation, options)
            .map(TrustDecision::Trusted)
    }

    pub(crate) fn evaluate_file_with_cli_policy<'a>(
        &self,
        artifact: &'a VerifiedFileEncArtifact,
        key_ctx: &'a KeyContext,
        options: OperationOptions,
        policy: &CliReadTrustPolicy,
    ) -> Result<TrustDecision<TrustedFileEncArtifact<'a>>> {
        let subject = artifact.recipient_set_subject()?;
        let requests =
            self.evaluate_read_artifact(artifact.inner().proof(), &subject, key_ctx, Some(policy))?;
        if !requests.is_empty() {
            return Ok(TrustDecision::ReviewRequired(requests));
        }
        TrustedFileEncArtifact::from_authorized(artifact, key_ctx, options)
            .map(TrustDecision::Trusted)
    }

    pub(crate) fn evaluate_kv_with_cli_policy<'a>(
        &self,
        artifact: &'a VerifiedKvEncArtifact,
        key_ctx: &'a KeyContext,
        operation: KvReadOperation,
        options: OperationOptions,
        policy: &CliReadTrustPolicy,
    ) -> Result<TrustDecision<TrustedKvEncArtifact<'a>>> {
        let subject = artifact.recipient_set_subject()?;
        let requests =
            self.evaluate_read_artifact(artifact.inner().proof(), &subject, key_ctx, Some(policy))?;
        if !requests.is_empty() {
            return Ok(TrustDecision::ReviewRequired(requests));
        }
        TrustedKvEncArtifact::from_authorized(artifact, key_ctx, operation, options)
            .map(TrustDecision::Trusted)
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
        self.enforce_store_owner(key_ctx)?;
        self.enforce_mutation_key_current(key_ctx)?;
        let self_trust = build_self_trust(key_ctx)?;
        let input = artifact.recipient_set_subject()?;
        let output = RecipientSetSubject::from_kv_mutation(artifact, recipients)?;
        let mut requests = self.evaluate_signer(artifact.inner().proof(), &self_trust)?;
        self.enforce_artifact_recipients_current(&input)?;
        self.evaluate_kv_output_recipients(&output, recipients, &self_trust, &mut requests)?;
        if !requests.is_empty() {
            return Ok(TrustDecision::ReviewRequired(requests));
        }
        AuthorizedKvMutation::from_authorized(artifact, recipients, key_ctx, options, operation)
            .map(TrustDecision::Trusted)
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

    fn evaluate_read_artifact(
        &self,
        proof: &SignatureVerificationProof,
        subject: &RecipientSetSubject,
        key_ctx: &KeyContext,
        policy: Option<&CliReadTrustPolicy>,
    ) -> Result<Vec<TrustReviewRequest>> {
        self.enforce_store_owner(key_ctx)?;
        let self_trust = build_self_trust(key_ctx)?;
        let mut requests = self.evaluate_signer_with_policy(proof, &self_trust, policy)?;
        self.evaluate_recipient_keys(subject, &self_trust, &mut requests)?;
        if policy.is_some_and(|policy| policy.skip_known_key_review) {
            requests.retain(|request| request.kind != TrustReviewKind::KnownKey);
        }
        Ok(requests)
    }

    fn evaluate_signer_with_policy(
        &self,
        proof: &SignatureVerificationProof,
        self_trust: &SelfTrustSet,
        policy: Option<&CliReadTrustPolicy>,
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
                accept_reviewed_non_member(proof, policy, error)
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
        resolve_signer_judgment(judgment)
    }

    fn evaluate_recipient_keys(
        &self,
        subject: &RecipientSetSubject,
        self_trust: &SelfTrustSet,
        requests: &mut Vec<TrustReviewRequest>,
    ) -> Result<()> {
        enforce_recipient_handle_consistency(subject, &self.members.members_by_kid)?;
        let identities = subject
            .inner
            .recipient_kids()
            .iter()
            .filter_map(|kid| self.members.members_by_kid.get(kid))
            .map(TrustIdentity::from_public_key)
            .collect::<Result<Vec<_>>>()?;
        self.evaluate_recipient_identities(&identities, self_trust, requests)
    }

    fn evaluate_output_recipient_keys(
        &self,
        recipients: &RecipientKeys,
        self_trust: &SelfTrustSet,
        requests: &mut Vec<TrustReviewRequest>,
    ) -> Result<()> {
        let identities = recipients
            .keys()
            .iter()
            .map(|key| {
                self.enforce_output_recipient_current(key.document())?;
                TrustIdentity::from_public_key(key.document())
            })
            .collect::<Result<Vec<_>>>()?;
        self.evaluate_recipient_identities(&identities, self_trust, requests)
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
        let output_kids = recipients
            .keys()
            .iter()
            .map(|key| key.document().protected.kid.as_str())
            .collect::<BTreeSet<_>>();
        let current_kids = self
            .members
            .members_by_kid
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if output_kids == current_kids && output_kids.len() == recipients.keys().len() {
            return Ok(());
        }
        Err(Error::build_verification_error(
            "E_TRUST_REJECTED".to_string(),
            "Output recipients must match all current members/active keys".to_string(),
        ))
    }

    fn evaluate_recipient_identities(
        &self,
        identities: &[TrustIdentity],
        self_trust: &SelfTrustSet,
        requests: &mut Vec<TrustReviewRequest>,
    ) -> Result<()> {
        let cache = AdditionalKnownKeyCache::new(self.known_keys(), &[]);
        cache.validate_recipient_integrity(identities)?;
        let pending = judge_recipients_trust(
            identities,
            &KnownKeyCache::new(self.known_keys()),
            self_trust,
        )?;
        for identity in pending {
            push_known_key_review_request(requests, identity.member_handle(), identity.kid());
        }
        Ok(())
    }

    fn enforce_artifact_recipients_current(&self, subject: &RecipientSetSubject) -> Result<()> {
        enforce_recipient_handle_consistency(subject, &self.members.members_by_kid)?;
        if let Some(kid) = subject
            .inner
            .recipient_kids()
            .iter()
            .find(|kid| !self.members.members_by_kid.contains_key(*kid))
        {
            return Err(build_inactive_recipient_error(kid));
        }
        Ok(())
    }

    fn enforce_output_recipient_current(&self, recipient: &PublicKey) -> Result<()> {
        let kid = &recipient.protected.kid;
        let Some(current) = self.members.members_by_kid.get(kid) else {
            return Err(build_inactive_recipient_error(kid));
        };
        if current == recipient {
            return Ok(());
        }
        Err(Error::build_verification_error(
            "E_ARTIFACT_RECIPIENT_KEY_MISMATCH".to_string(),
            format!("Output recipient kid '{}' differs from members/active", kid),
        ))
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
        let kind = match judge_recipient_set(self.recipient_sets(), &subject.inner) {
            RecipientSetJudgment::Accepted => return Ok(()),
            RecipientSetJudgment::Missing => TrustReviewKind::RecipientSet,
            RecipientSetJudgment::Changed { .. } => TrustReviewKind::ChangedRecipientSet,
        };
        requests.push(recipient_review_request(kind, &subject.inner));
        Ok(())
    }

    fn known_keys(&self) -> &[KnownKey] {
        self.store
            .as_ref()
            .map(|store| store.inner().document().protected.known_keys.as_slice())
            .unwrap_or(&[])
    }

    fn recipient_sets(&self) -> &[RecipientSetRecord] {
        self.store
            .as_ref()
            .map(|store| store.inner().document().protected.recipient_sets.as_slice())
            .unwrap_or(&[])
    }

    /// Evaluate whether a key owner is already approved.
    pub fn evaluate_known_key(&self, subject_handle: &str, kid: &str) -> Result<TrustDecision> {
        match judge_known_key(self.known_keys(), kid, subject_handle)? {
            KnownKeyJudgment::Existing => Ok(TrustDecision::Trusted(())),
            KnownKeyJudgment::New => Ok(TrustDecision::ReviewRequired(vec![TrustReviewRequest {
                kind: TrustReviewKind::KnownKey,
                subject_handle: Some(subject_handle.to_string()),
                kid: Some(kid.to_string()),
                sid: None,
                recipient_kids: Vec::new(),
                recipient_handle_hints: Vec::new(),
            }])),
        }
    }

    /// Evaluate whether an artifact recipient set is already approved.
    pub fn evaluate_recipient_set(&self, subject: &RecipientSetSubject) -> Result<TrustDecision> {
        match judge_recipient_set(self.recipient_sets(), &subject.inner) {
            RecipientSetJudgment::Accepted => Ok(TrustDecision::Trusted(())),
            RecipientSetJudgment::Missing => Ok(TrustDecision::ReviewRequired(vec![
                recipient_review_request(TrustReviewKind::RecipientSet, &subject.inner),
            ])),
            RecipientSetJudgment::Changed { .. } => Ok(TrustDecision::ReviewRequired(vec![
                recipient_review_request(TrustReviewKind::ChangedRecipientSet, &subject.inner),
            ])),
        }
    }
}

/// Turn one signer judgment into the review it asks for or the error it states.
fn resolve_signer_judgment(judgment: TrustJudgment) -> Result<Vec<TrustReviewRequest>> {
    match judgment {
        TrustJudgment::Trusted => Ok(Vec::new()),
        TrustJudgment::NeedsApproval { member_handle, kid } => {
            Ok(vec![known_key_review_request(&member_handle, &kid)])
        }
        TrustJudgment::NonMember { member_handle, kid } => {
            Err(build_non_member_error(&member_handle, &kid))
        }
        TrustJudgment::ActiveMemberMismatch {
            member_handle,
            kid,
            active_member_handle,
        } => Err(build_active_member_mismatch_error(
            &member_handle,
            &kid,
            &active_member_handle,
        )),
        TrustJudgment::KnownKeyIntegrityAnomaly {
            member_handle,
            kid,
            known_member_handle,
        } => Err(build_known_key_integrity_error(
            &member_handle,
            &kid,
            &known_member_handle,
        )),
    }
}

/// Accept a signer the trust rules rejected as a non-member, but only when the
/// policy names the exact identity a review already accepted.
fn accept_reviewed_non_member(
    proof: &SignatureVerificationProof,
    policy: Option<&CliReadTrustPolicy>,
    error: Error,
) -> Result<Vec<TrustReviewRequest>> {
    let Some(public_key) = proof.signer_public_key.as_ref() else {
        return Err(error);
    };
    let identity = TrustIdentity::from_public_key(public_key)?;
    let accepted = policy
        .and_then(|policy| policy.accepted_non_member.as_ref())
        .is_some_and(|(handle, kid)| handle == identity.member_handle() && kid == identity.kid());
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

fn known_key_review_request(member_handle: &MemberHandle, kid: &Kid) -> TrustReviewRequest {
    TrustReviewRequest {
        kind: TrustReviewKind::KnownKey,
        subject_handle: Some(member_handle.to_string()),
        kid: Some(kid.to_string()),
        sid: None,
        recipient_kids: Vec::new(),
        recipient_handle_hints: Vec::new(),
    }
}

fn push_known_key_review_request(
    requests: &mut Vec<TrustReviewRequest>,
    member_handle: &str,
    kid: &str,
) {
    let duplicate = requests.iter().any(|request| {
        request.kind == TrustReviewKind::KnownKey
            && request.subject_handle() == Some(member_handle)
            && request.kid() == Some(kid)
    });
    if !duplicate {
        requests.push(TrustReviewRequest {
            kind: TrustReviewKind::KnownKey,
            subject_handle: Some(member_handle.to_string()),
            kid: Some(kid.to_string()),
            sid: None,
            recipient_kids: Vec::new(),
            recipient_handle_hints: Vec::new(),
        });
    }
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
             Action: Run kapsaro rewrap before writing.",
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

fn build_non_member_error(member_handle: &MemberHandle, kid: &Kid) -> Error {
    Error::build_verification_error(
        "E_TRUST_NON_MEMBER".to_string(),
        format!(
            "Signer is not in active members.\nsigner: {}\nkid: {}",
            member_handle, kid
        ),
    )
}

fn build_active_member_mismatch_error(
    member_handle: &MemberHandle,
    kid: &Kid,
    active_member_handle: &MemberHandle,
) -> Error {
    Error::build_verification_error(
        "E_TRUST_ACTIVE_MEMBER_MISMATCH".to_string(),
        format!(
            "Signer '{}' (kid: {}) does not match current active member '{}'",
            member_handle, kid, active_member_handle
        ),
    )
}

fn build_known_key_integrity_error(
    member_handle: &MemberHandle,
    kid: &Kid,
    known_member_handle: &MemberHandle,
) -> Error {
    Error::build_verification_error(
        "E_TRUST_KID_INTEGRITY_ANOMALY".to_string(),
        format!(
            "kid '{}' exists with subject_handle '{}' but candidate has subject_handle '{}'",
            kid, known_member_handle, member_handle
        ),
    )
}

impl RecipientSetSubject {
    pub(crate) fn from_verified_file(document: &VerifiedFileEncDocument) -> Result<Self> {
        file_recipient_evidence(document.document())
            .map(|evidence| Self::from_inner(evidence.recipient_set))
    }

    pub(crate) fn from_verified_kv(document: &VerifiedKvEncDocument) -> Result<Self> {
        kv_recipient_evidence(document.document())
            .map(|evidence| Self::from_inner(evidence.recipient_set))
    }

    fn from_kv_mutation(
        artifact: &VerifiedKvEncArtifact,
        recipients: &RecipientKeys,
    ) -> Result<Self> {
        let sid = artifact.inner().document().head().sid;
        Self::from_output_recipients(sid, recipients)
    }

    fn from_output_recipients(sid: uuid::Uuid, recipients: &RecipientKeys) -> Result<Self> {
        let public_keys = recipients
            .keys()
            .iter()
            .map(|key| key.document().clone())
            .collect::<Vec<_>>();
        ArtifactRecipientSet::from_public_keys(sid, &public_keys).map(Self::from_inner)
    }

    /// Return the artifact recipient-set ID.
    pub fn sid(&self) -> uuid::Uuid {
        self.inner.sid()
    }

    /// Return canonical recipient key IDs.
    pub fn recipient_kids(&self) -> &[String] {
        self.inner.recipient_kids()
    }

    fn from_inner(inner: ArtifactRecipientSet) -> Self {
        Self { inner }
    }
}

impl VerifiedLocalTrustStoreLoadResult {
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
}

impl TrustReviewRequest {
    /// Return the review request category.
    pub fn kind(&self) -> TrustReviewKind {
        self.kind
    }

    /// Return the subject handle for known-key review requests.
    pub fn subject_handle(&self) -> Option<&str> {
        self.subject_handle.as_deref()
    }

    /// Return the key ID for known-key review requests.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Return the artifact recipient-set ID for recipient-set review requests.
    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    /// Return the recipient key IDs for recipient-set review requests.
    pub fn recipient_kids(&self) -> &[String] {
        &self.recipient_kids
    }

    /// Return display-only recipient identity hints for recipient-set review.
    pub fn recipient_handle_hints(&self) -> &[TrustRecipientHandleHint] {
        &self.recipient_handle_hints
    }
}

impl TrustRecipientHandleHint {
    /// Return the recipient key ID.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Return the recipient member handle.
    pub fn recipient_handle(&self) -> &str {
        &self.recipient_handle
    }

    fn from_model(hint: &RecipientHandleHint) -> Self {
        Self {
            kid: hint.kid.clone(),
            recipient_handle: hint.recipient_handle.clone(),
        }
    }

    fn into_model(self) -> RecipientHandleHint {
        RecipientHandleHint {
            kid: self.kid,
            recipient_handle: self.recipient_handle,
        }
    }
}

impl TrustApproval {
    /// Build a known-key approval.
    pub fn known_key(subject_handle: impl Into<String>, kid: impl Into<String>) -> Self {
        Self {
            kind: TrustApprovalKind::KnownKey(KnownKeyApproval {
                subject_handle: subject_handle.into(),
                kid: kid.into(),
            }),
        }
    }

    /// Build a recipient-set approval.
    pub fn recipient_set(sid: uuid::Uuid, recipient_kids: Vec<String>) -> Self {
        Self {
            kind: TrustApprovalKind::RecipientSet(RecipientSetApproval {
                sid,
                recipient_kids,
                recipient_handle_hints: Vec::new(),
            }),
        }
    }

    /// Build an approval from a review request.
    pub fn from_request(request: &TrustReviewRequest) -> Result<Self> {
        match request.kind {
            TrustReviewKind::KnownKey => Ok(Self::known_key(
                require_review_field(request.subject_handle(), "subject_handle")?,
                require_review_field(request.kid(), "kid")?,
            )),
            TrustReviewKind::RecipientSet | TrustReviewKind::ChangedRecipientSet => {
                let sid = require_review_field(request.sid(), "sid")?;
                let sid = uuid::Uuid::parse_str(sid)
                    .map_err(|error| Error::build_invalid_sid_error(sid, error))?;
                Ok(Self {
                    kind: TrustApprovalKind::RecipientSet(RecipientSetApproval {
                        sid,
                        recipient_kids: request.recipient_kids.clone(),
                        recipient_handle_hints: request.recipient_handle_hints.clone(),
                    }),
                })
            }
        }
    }
}

impl KnownKeyApproval {
    fn into_known_key(self, approved_at: String) -> Result<KnownKey> {
        let identity = KnownKeyIdentity::try_new(self.subject_handle, self.kid)?;
        Ok(KnownKey {
            kid: identity.kid().to_string(),
            subject_handle: identity.member_handle().to_string(),
            approved_at,
            approved_via: KnownKeyApprovalVia::ManualReview,
            evidence: None,
            extra: BTreeMap::new(),
        })
    }
}

fn require_review_field<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str> {
    value.ok_or_else(|| {
        Error::build_invalid_argument_error(format!("Trust review request is missing {}", field))
    })
}

fn recipient_review_request(
    kind: TrustReviewKind,
    current: &ArtifactRecipientSet,
) -> TrustReviewRequest {
    TrustReviewRequest {
        kind,
        subject_handle: None,
        kid: None,
        sid: Some(current.sid_string()),
        recipient_kids: current.recipient_kids().to_vec(),
        recipient_handle_hints: current
            .recipient_handle_hints()
            .iter()
            .map(TrustRecipientHandleHint::from_model)
            .collect(),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/api_trust_store_mutation_test.rs"]
mod api_trust_store_mutation_test;

#[cfg(test)]
#[path = "../../tests/unit/internal/api_trust_read_test.rs"]
mod api_trust_read_test;
