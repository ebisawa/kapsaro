// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Non-interactive local trust store facade.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::feature::context::crypto::build_signing_context;
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
use crate::feature::trust::signature::sign_trust_store;
use crate::feature::trust::verification::verify_trust_store;
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
};
use crate::io::trust::paths::{get_trust_store_dir, get_trust_store_file_path};
use crate::io::trust::store::{load_trust_store, load_trust_store_at, save_trust_store_at};
use crate::io::workspace::members::load_active_member_files;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, RecipientHandleHint, TrustStoreDocument, TrustStoreProtected,
};
use crate::model::trust_store_verified::VerifiedTrustStore;
use crate::model::{file_enc::VerifiedFileEncDocument, kv_enc::verified::VerifiedKvEncDocument};
use crate::support::fs::relative::DirectoryFd;
use crate::support::fs::{ensure_dir_restricted, lock};
use crate::support::time::generate_current_timestamp;
use crate::{Error, Result};

use super::file::{FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact};
use super::key::{KeyContext, LocalKeyStore, RecipientKeys};
use super::kv::{
    AuthorizedKvMutation, KvMutationOperation, KvReadOperation, TrustedKvEncArtifact,
    VerifiedKvEncArtifact,
};
use super::operation::OperationOptions;

/// Filesystem-backed local trust store for one owner.
#[derive(Debug, Clone)]
pub struct LocalTrustStore {
    base_dir: PathBuf,
    owner_handle: String,
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

struct RawTrustStoreLoadResult {
    document: TrustStoreDocument,
    permission_warnings: Vec<String>,
}

/// Loaded and verified local trust store with non-fatal permission warnings.
#[derive(Debug)]
pub struct VerifiedLocalTrustStoreLoadResult {
    store: VerifiedLocalTrustStore,
    permission_warnings: Vec<String>,
}

impl LocalTrustStore {
    /// Build a trust store facade from `<KAPSARO_HOME>` and owner handle.
    pub fn new(base_dir: impl Into<PathBuf>, owner_handle: String) -> Self {
        Self {
            base_dir: base_dir.into(),
            owner_handle,
        }
    }

    /// Return the backing trust store file path.
    pub fn path(&self) -> PathBuf {
        get_trust_store_file_path(&self.base_dir, &self.owner_handle)
    }

    /// Load and verify the local trust store, preserving any permission warnings.
    pub fn load_verified(
        &self,
        key_store: &LocalKeyStore,
    ) -> Result<Option<VerifiedLocalTrustStoreLoadResult>> {
        self.load_raw_with_warnings()?.map_or(Ok(None), |loaded| {
            verify_trust_store(&loaded.document, key_store.root()).map(|store| {
                Some(VerifiedLocalTrustStoreLoadResult {
                    store: VerifiedLocalTrustStore::from_inner(store),
                    permission_warnings: loaded.permission_warnings,
                })
            })
        })
    }

    /// Apply caller-approved updates, re-sign, and save atomically.
    pub fn apply_approvals(
        &self,
        approvals: Vec<TrustApproval>,
        key_ctx: &KeyContext,
    ) -> Result<()> {
        self.ensure_owner_key_context(key_ctx)?;
        let signing = build_signing_context(key_ctx.inner())?;
        let keystore_root = key_ctx.keystore_root().ok_or_else(|| {
            Error::build_invalid_operation_error(
                "Key context is not backed by a local keystore".to_string(),
            )
        })?;
        let trust_dir = get_trust_store_dir(&self.base_dir);
        ensure_dir_restricted(&trust_dir)?;
        let path = self.path();
        lock::with_locked_dir(&trust_dir, |locked_trust_dir| {
            let mut protected =
                self.load_protected_for_mutation_at(locked_trust_dir, &path, keystore_root)?;
            self.apply_approval_updates(&mut protected, approvals)?;
            protected.updated_at = generate_current_timestamp()?;
            let document =
                sign_trust_store(&protected, signing.signing_key(), signing.signer_kid())?;
            save_trust_store_at(locked_trust_dir, &path, &document)
        })
    }

    fn apply_approval_updates(
        &self,
        protected: &mut TrustStoreProtected,
        approvals: Vec<TrustApproval>,
    ) -> Result<()> {
        for approval in approvals {
            self.apply_approval_update(protected, approval)?;
        }
        Ok(())
    }

    fn apply_approval_update(
        &self,
        protected: &mut TrustStoreProtected,
        approval: TrustApproval,
    ) -> Result<()> {
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
    ) -> Result<()> {
        let known_key = key.into_known_key(generate_current_timestamp()?)?;
        if known_key.subject_handle == self.owner_handle {
            return Err(Error::build_invalid_operation_error(format!(
                "Self member '{}' must not be stored in known_keys",
                self.owner_handle
            )));
        }
        add_known_key(&mut protected.known_keys, known_key)?;
        Ok(())
    }

    fn ensure_owner_key_context(&self, key_ctx: &KeyContext) -> Result<()> {
        if key_ctx.member_handle() != self.owner_handle {
            return Err(Error::build_invalid_argument_error(format!(
                "Key context member_handle '{}' does not match trust store owner_handle '{}'",
                key_ctx.member_handle(),
                self.owner_handle
            )));
        }
        Ok(())
    }

    fn load_protected_for_mutation_at<D>(
        &self,
        dir: &D,
        path: &Path,
        keystore_root: &Path,
    ) -> Result<TrustStoreProtected>
    where
        D: DirectoryFd,
    {
        let Some(loaded) = self.load_raw_with_warnings_at_dir(dir, path)? else {
            return empty_protected(&self.owner_handle);
        };
        let verified = verify_trust_store(&loaded.document, keystore_root)?;
        let (document, _) = verified.into_inner();
        Ok(document.protected)
    }

    fn load_raw_with_warnings(&self) -> Result<Option<RawTrustStoreLoadResult>> {
        self.load_raw_with_warnings_at(&self.path())
    }

    fn load_raw_with_warnings_at(&self, path: &Path) -> Result<Option<RawTrustStoreLoadResult>> {
        load_trust_store(path, &self.base_dir).map(|loaded| {
            loaded.map(|result| RawTrustStoreLoadResult {
                document: result.document,
                permission_warnings: result.permission_warnings,
            })
        })
    }

    fn load_raw_with_warnings_at_dir<D>(
        &self,
        dir: &D,
        path: &Path,
    ) -> Result<Option<RawTrustStoreLoadResult>>
    where
        D: DirectoryFd,
    {
        load_trust_store_at(dir, path, &self.base_dir).map(|loaded| {
            loaded.map(|result| RawTrustStoreLoadResult {
                document: result.document,
                permission_warnings: result.permission_warnings,
            })
        })
    }
}

fn apply_recipient_set_approval(
    protected: &mut TrustStoreProtected,
    approval: RecipientSetApproval,
) -> Result<()> {
    let hints = approval
        .recipient_handle_hints
        .into_iter()
        .map(TrustRecipientHandleHint::into_model)
        .collect();
    let recipient_set =
        ArtifactRecipientSet::from_parts(approval.sid, approval.recipient_kids, hints)?;
    upsert_recipient_set(
        &mut protected.recipient_sets,
        recipient_set,
        generate_current_timestamp()?,
    );
    Ok(())
}

impl CurrentMemberSnapshot {
    /// Load and verify the current active members from a workspace.
    pub fn load(workspace_path: &Path) -> Result<Self> {
        let members = load_active_member_files(workspace_path)?;
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
        proof: &crate::model::verification::SignatureVerificationProof,
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
        proof: &crate::model::verification::SignatureVerificationProof,
        self_trust: &SelfTrustSet,
        policy: Option<&CliReadTrustPolicy>,
    ) -> Result<Vec<TrustReviewRequest>> {
        match self.evaluate_signer(proof, self_trust) {
            Ok(requests) => Ok(requests),
            Err(error) if error.verification_rule() == Some("E_TRUST_NON_MEMBER") => {
                let Some(public_key) = proof.signer_public_key.as_ref() else {
                    return Err(error);
                };
                let identity = TrustIdentity::from_public_key(public_key)?;
                let accepted = policy
                    .and_then(|policy| policy.accepted_non_member.as_ref())
                    .is_some_and(|(handle, kid)| {
                        handle == identity.member_handle() && kid == identity.kid()
                    });
                if accepted {
                    Ok(Vec::new())
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    fn enforce_store_owner(&self, key_ctx: &KeyContext) -> Result<()> {
        let Some(store) = self.store.as_ref() else {
            return Ok(());
        };
        let owner_handle = &store.inner().document().protected.owner_handle;
        if owner_handle == key_ctx.member_handle() {
            return Ok(());
        }
        Err(Error::build_invalid_argument_error(format!(
            "Trust store owner_handle '{}' does not match key context member_handle '{}'",
            owner_handle,
            key_ctx.member_handle()
        )))
    }

    fn enforce_mutation_key_current(&self, key_ctx: &KeyContext) -> Result<()> {
        let Some(current) = self.members.members_by_kid.get(key_ctx.kid()) else {
            return Err(build_inactive_mutation_key_error(key_ctx));
        };
        if current.protected.subject_handle == key_ctx.member_handle()
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
        proof: &crate::model::verification::SignatureVerificationProof,
        self_trust: &SelfTrustSet,
    ) -> Result<Vec<TrustReviewRequest>> {
        let public_key = proof.signer_public_key.as_ref().ok_or_else(|| {
            Error::build_verification_error(
                "E_SIGNER_PUB_MISSING".to_string(),
                "Required signer_pub is missing from verified proof".to_string(),
            )
        })?;
        let identity = TrustIdentity::from_public_key(public_key)?;
        let judgment = judge_signer_trust(
            &identity,
            &self.members.active_members(),
            &KnownKeyCache::new(self.known_keys()),
            self_trust,
        )?;
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

    fn recipient_sets(&self) -> &[crate::model::trust_store::RecipientSetRecord] {
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

fn build_self_trust(key_ctx: &KeyContext) -> Result<SelfTrustSet> {
    let sig_x = [key_ctx.inner().self_signature_public_key_x()];
    match key_ctx.keystore_root() {
        Some(root) => {
            SelfTrustSet::try_new_with_keystore(key_ctx.member_handle(), sig_x, root.to_path_buf())
        }
        None => SelfTrustSet::try_new(key_ctx.member_handle(), sig_x),
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

    /// Return non-fatal permission warnings observed while loading.
    pub fn permission_warnings(&self) -> &[String] {
        &self.permission_warnings
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

fn empty_protected(owner_handle: &str) -> Result<crate::model::trust_store::TrustStoreProtected> {
    let now = generate_current_timestamp()?;
    Ok(crate::model::trust_store::TrustStoreProtected {
        format: crate::model::wire::format::LOCAL_TRUST_V1.to_string(),
        owner_handle: owner_handle.to_string(),
        created_at: now.clone(),
        updated_at: now,
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
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
