// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Non-interactive local trust store facade.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::feature::envelope::signature::build_signing_context;
use crate::feature::trust::known_keys::{
    add_known_key, judge_known_key, KnownKeyIdentity, KnownKeyJudgment,
};
use crate::feature::trust::recipient_sets::{
    judge_recipient_set, validate_recipient_set_record, ArtifactRecipientSet, RecipientSetJudgment,
};
use crate::feature::trust::signature::sign_trust_store;
use crate::feature::trust::verification::verify_trust_store;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::{load_trust_store, save_trust_store};
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, RecipientSetRecord, TrustStoreDocument, TrustStoreProtected,
};
use crate::model::trust_store_verified::VerifiedTrustStore;
use crate::model::{file_enc::VerifiedFileEncDocument, kv_enc::verified::VerifiedKvEncDocument};
use crate::support::fs::lock;
use crate::support::time::generate_current_timestamp;
use crate::{Error, Result};

use super::key::{KeyContext, LocalKeyStore};

/// Filesystem-backed local trust store for one owner.
#[derive(Debug, Clone)]
pub struct LocalTrustStore {
    base_dir: PathBuf,
    owner_handle: String,
}

/// Pure trust policy evaluator.
#[derive(Debug, Clone)]
pub struct TrustPolicyEvaluator {
    store: Option<VerifiedLocalTrustStore>,
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
pub enum TrustDecision {
    Accepted,
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
    /// Build a trust store facade from `<SECRETENV_HOME>` and owner handle.
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

    /// Load and verify the local trust store if it exists.
    pub fn load_verified(
        &self,
        key_store: &LocalKeyStore,
    ) -> Result<Option<VerifiedLocalTrustStore>> {
        self.load_verified_with_warnings(key_store)
            .map(|loaded| loaded.map(|result| result.store))
    }

    /// Load and verify the document, preserving any permission warnings.
    pub fn load_verified_with_warnings(
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
        let signing = build_signing_context(key_ctx.inner(), false)?;
        let keystore_root = key_ctx.keystore_root().ok_or_else(|| {
            Error::build_invalid_operation_error(
                "Key context is not backed by a local keystore".to_string(),
            )
        })?;
        let path = self.path();
        lock::with_file_lock(&path, || {
            let mut protected = self.load_protected_for_mutation(&path, keystore_root)?;
            self.apply_approval_updates(&mut protected, approvals)?;
            protected.updated_at = generate_current_timestamp()?;
            let document =
                sign_trust_store(&protected, signing.signing_key(), signing.signer_kid())?;
            save_trust_store(&path, &document)
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

    fn load_protected_for_mutation(
        &self,
        path: &Path,
        keystore_root: &Path,
    ) -> Result<TrustStoreProtected> {
        let Some(loaded) = self.load_raw_with_warnings_at(path)? else {
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
}

fn apply_recipient_set_approval(
    protected: &mut TrustStoreProtected,
    approval: RecipientSetApproval,
) -> Result<()> {
    let record = approval.into_record(generate_current_timestamp()?)?;
    validate_recipient_set_record(&record)?;
    upsert_record_by_sid(&mut protected.recipient_sets, record);
    Ok(())
}

impl TrustPolicyEvaluator {
    /// Build an evaluator from an optional verified trust store.
    pub fn new(store: Option<VerifiedLocalTrustStore>) -> Self {
        Self { store }
    }

    /// Evaluate whether a key owner is already approved.
    pub fn evaluate_known_key(&self, subject_handle: &str, kid: &str) -> Result<TrustDecision> {
        let keys = self
            .store
            .as_ref()
            .map(|store| store.inner().document().protected.known_keys.as_slice())
            .unwrap_or(&[]);
        match judge_known_key(keys, kid, subject_handle)? {
            KnownKeyJudgment::Existing => Ok(TrustDecision::Accepted),
            KnownKeyJudgment::New => Ok(TrustDecision::ReviewRequired(vec![TrustReviewRequest {
                kind: TrustReviewKind::KnownKey,
                subject_handle: Some(subject_handle.to_string()),
                kid: Some(kid.to_string()),
                sid: None,
                recipient_kids: Vec::new(),
            }])),
        }
    }

    /// Evaluate whether an artifact recipient set is already approved.
    pub fn evaluate_recipient_set(&self, subject: &RecipientSetSubject) -> Result<TrustDecision> {
        let records = self
            .store
            .as_ref()
            .map(|store| store.inner().document().protected.recipient_sets.as_slice())
            .unwrap_or(&[]);
        match judge_recipient_set(records, &subject.inner) {
            RecipientSetJudgment::Accepted => Ok(TrustDecision::Accepted),
            RecipientSetJudgment::Missing => Ok(TrustDecision::ReviewRequired(vec![
                recipient_review_request(TrustReviewKind::RecipientSet, &subject.inner),
            ])),
            RecipientSetJudgment::Changed { .. } => Ok(TrustDecision::ReviewRequired(vec![
                recipient_review_request(TrustReviewKind::ChangedRecipientSet, &subject.inner),
            ])),
        }
    }
}

impl RecipientSetSubject {
    pub(crate) fn from_verified_file(document: &VerifiedFileEncDocument) -> Result<Self> {
        let document = document.document();
        ArtifactRecipientSet::from_wrap_items(document.protected.sid, &document.protected.wrap)
            .map(Self::from_inner)
    }

    pub(crate) fn from_verified_kv(document: &VerifiedKvEncDocument) -> Result<Self> {
        let document = document.document();
        ArtifactRecipientSet::from_wrap_items(document.head.sid, &document.wrap.wrap)
            .map(Self::from_inner)
    }

    /// Return the artifact recipient-set ID.
    pub fn sid(&self) -> uuid::Uuid {
        self.inner.sid()
    }

    /// Return the artifact recipient-set ID as a string.
    pub fn sid_string(&self) -> String {
        self.inner.sid_string()
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
                let sid = uuid::Uuid::parse_str(sid).map_err(|error| {
                    Error::build_invalid_argument_error(format!("Invalid sid '{}': {}", sid, error))
                })?;
                Ok(Self::recipient_set(sid, request.recipient_kids.clone()))
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

impl RecipientSetApproval {
    fn into_record(self, approved_at: String) -> Result<RecipientSetRecord> {
        ArtifactRecipientSet::new(self.sid, self.recipient_kids)
            .map(|set| set.into_record(approved_at))
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
        format: crate::model::wire::format::LOCAL_TRUST_V5.to_string(),
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
    }
}

fn upsert_record_by_sid(records: &mut Vec<RecipientSetRecord>, record: RecipientSetRecord) {
    if let Some(existing) = records
        .iter_mut()
        .find(|existing| existing.sid == record.sid)
    {
        *existing = record;
    } else {
        records.push(record);
    }
}
