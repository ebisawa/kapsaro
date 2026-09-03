// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Fixed-capability workspace read authorization session.
//! Re-evaluates reviewed file and KV reads against current trusted state.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use uuid::Uuid;

use crate::io::trust::paths::TRUST_DIR_NAME;
use crate::io::workspace::setup::SECRETS_DIR_NAME;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::read::open_regular_file;
use crate::support::fs::relative::{
    open_child_dir, open_dir_identity, open_optional_child_dir, DirectoryScope, OpenDir,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

use super::config::LocalStateSession;
use super::file::{
    FileEncArtifact, FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact,
};
use super::key::{KeyContext, Kid, MemberHandle};
use super::kv::{KvEncArtifact, KvReadOperation, TrustedKvEncArtifact, VerifiedKvEncArtifact};
use super::operation::OperationOptions;
use super::trust::recovery::{
    build_trust_store_reset_plan_from_read_session, observe_trust_store_recovery_from_read_session,
    TrustStoreRecoveryToken, TrustStoreResetPlan,
};
use super::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, KnownKeyReview, KnownKeyReviewCandidate,
    LocalTrustStore, NonMemberSignerReview, ReadTrustExceptions, ReadTrustReview, TrustApproval,
    TrustApprovalOutcome, TrustDecision, TrustPolicyEvaluator, TrustReviewRequest,
};

/// A read decision that either grants a capability or returns opaque review state.
pub enum ReadSessionDecision<T> {
    Authorized(AuthorizedRead<T>),
    ReviewRequired(Box<ReadReview>),
}

/// A trust-authorized value with warnings collected during the same evaluation.
pub struct AuthorizedRead<T> {
    value: T,
    unresolved_recipient_kids: Vec<Kid>,
}

/// Displayable identity for a cryptographically verified non-member signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonMemberReadReview {
    candidate: KnownKeyReviewCandidate,
    recipient_handles: Vec<MemberHandle>,
}

/// Opaque review state bound to one artifact, operation, and signer identity.
pub struct ReadReview {
    binding: ReadReviewBinding,
    requests: Vec<TrustReviewRequest>,
    first_request_is_signer: bool,
    non_member_signer: Option<NonMemberReadReview>,
    unresolved_recipient_kids: Vec<Kid>,
    allow_non_member: bool,
    acceptance_issued: bool,
    accepted_non_member: Option<AcceptedNonMember>,
    source: ReadSource,
}

/// Opaque one-shot acceptance minted only from a [`ReadReview`].
///
/// ```compile_fail
/// use kapsaro_core::api::trust::ReadAcceptance;
///
/// let _forged = ReadAcceptance::new();
/// ```
pub struct ReadAcceptance {
    review_id: Uuid,
    digest: [u8; 32],
    operation: ReadOperationBinding,
    signer: (MemberHandle, Kid),
}

/// Fixed workspace, secrets, trust, and local-state directory capabilities.
pub struct WorkspaceReadSession<'a> {
    workspace: AnchoredDir,
    secrets_dir: Arc<OpenDir>,
    home: Option<AnchoredDir>,
    trust_dir: OnceLock<Arc<OpenDir>>,
    key_ctx: &'a KeyContext,
    options: OperationOptions,
    known_key_review: KnownKeyReview,
}

/// Opaque fixed directories used by one workspace read command.
pub struct WorkspaceReadDirectories {
    workspace: AnchoredDir,
    secrets_dir: Arc<OpenDir>,
    home: Option<AnchoredDir>,
}

/// File content capability retained for one read command and all of its reviews.
pub struct FileReadTarget {
    source: ReadSource,
}

#[derive(Clone, PartialEq, Eq)]
struct ReadReviewBinding {
    review_id: Uuid,
    digest: [u8; 32],
    operation: ReadOperationBinding,
}

#[derive(Clone)]
struct AcceptedNonMember {
    review_id: Uuid,
    digest: [u8; 32],
    operation: ReadOperationBinding,
    signer: (MemberHandle, Kid),
}

struct ReadEvaluationState {
    binding: ReadReviewBinding,
    source: ReadSource,
    acceptance: Option<ReadAcceptance>,
    accepted_non_member: Option<AcceptedNonMember>,
}

#[derive(Clone, PartialEq, Eq)]
enum ReadOperationBinding {
    File(FileReadOperation),
    Kv(KvReadOperation),
}

#[derive(Clone)]
enum ReadSource {
    File {
        file: Arc<File>,
        source_name: String,
    },
    Content {
        raw: Arc<String>,
        source_name: String,
    },
    Kv {
        name: String,
    },
}

impl<'a> WorkspaceReadSession<'a> {
    /// Open a read session using caller-fixed local-state capabilities.
    pub fn open_with_local_state(
        workspace_path: impl AsRef<Path>,
        local_state: Option<&LocalStateSession>,
        key_ctx: &'a KeyContext,
        options: OperationOptions,
    ) -> Result<Self> {
        let (workspace, secrets_dir) = open_workspace_directories(workspace_path.as_ref())?;
        let key_home = key_ctx
            .inner()
            .local_keystore_access()
            .and_then(|keystore| keystore.home())
            .cloned();
        let local_state_home = local_state.and_then(LocalStateSession::home).cloned();
        let home = select_local_state_home(local_state_home, key_home)?;
        Ok(Self::from_directories(
            WorkspaceReadDirectories {
                workspace,
                secrets_dir,
                home,
            },
            key_ctx,
            options,
        ))
    }

    /// Bind fixed workspace directories to the explicit key and operation options.
    pub fn from_directories(
        directories: WorkspaceReadDirectories,
        key_ctx: &'a KeyContext,
        options: OperationOptions,
    ) -> Self {
        Self {
            workspace: directories.workspace,
            secrets_dir: directories.secrets_dir,
            home: directories.home,
            trust_dir: OnceLock::new(),
            key_ctx,
            options,
            known_key_review: KnownKeyReview::Required,
        }
    }

    /// Configure whether known signer and recipient keys require local review.
    pub fn with_known_key_review(mut self, review: KnownKeyReview) -> Self {
        self.known_key_review = review;
        self
    }

    /// Observe the exact trust store a later recovery offer may reset.
    pub fn observe_trust_store_recovery(&self) -> TrustStoreRecoveryToken {
        observe_trust_store_recovery_from_read_session(self)
    }

    /// Build an identity-bound reset plan for a trust-store read failure.
    pub fn build_trust_store_reset_plan(
        &self,
        token: TrustStoreRecoveryToken,
        error: Error,
        confirmation_available: bool,
    ) -> Result<TrustStoreResetPlan> {
        build_trust_store_reset_plan_from_read_session(self, token, error, confirmation_available)
    }

    /// Persist reviewed recipient key approvals through the fixed trust capability.
    pub fn apply_approvals(&self, approvals: Vec<TrustApproval>) -> Result<TrustApprovalOutcome> {
        let home = self.home.as_ref().ok_or_else(|| {
            Error::build_invalid_operation_error(
                "Local state is required to save trust approvals".to_string(),
            )
        })?;
        let trust_dir = self.ensured_trust_directory()?;
        LocalTrustStore::open_from_anchored_base(home, self.key_ctx.member_handle().clone())
            .apply_approvals_with_conflict_handling_at(
                trust_dir,
                approvals,
                self.key_ctx,
                ApprovalConflictHandling::merge(),
            )
    }

    /// Load a KV artifact through the fixed secrets directory.
    pub fn load_kv_artifact(&self, name: &str) -> Result<KvEncArtifact> {
        KvEncArtifact::load_at(self.secrets_dir.as_ref(), name)
    }

    /// Open and retain the exact regular file one read command will review.
    pub fn open_file_read_target(&self, path: impl AsRef<Path>) -> Result<FileReadTarget> {
        let path = path.as_ref();
        Ok(FileReadTarget {
            source: ReadSource::File {
                file: Arc::new(open_regular_file(path)?),
                source_name: format_path_relative_to_cwd(path),
            },
        })
    }

    /// Read stdin-like content once and retain its verified bytes for all reviews.
    pub fn capture_file_read_target(
        &self,
        reader: impl std::io::Read,
        source_name: impl Into<String>,
    ) -> Result<FileReadTarget> {
        let source_name = source_name.into();
        let artifact = FileEncArtifact::load_reader(reader, source_name.clone())?;
        Ok(FileReadTarget {
            source: ReadSource::Content {
                raw: Arc::new(artifact.as_str().to_string()),
                source_name,
            },
        })
    }

    /// Verify and evaluate a file artifact through its retained file capability.
    pub fn begin_file_read(
        &self,
        target: &FileReadTarget,
        operation: FileReadOperation,
        allow_non_member: bool,
    ) -> Result<ReadSessionDecision<TrustedFileEncArtifact<'a>>> {
        let source = target.source.clone();
        let artifact = self.load_verified_file(&source)?;
        let binding = ReadReviewBinding::new(
            artifact.binding_digest()?,
            ReadOperationBinding::File(operation),
        );
        self.evaluate_file(
            artifact,
            operation,
            allow_non_member,
            ReadEvaluationState {
                binding,
                source,
                acceptance: None,
                accepted_non_member: None,
            },
        )
    }

    /// Re-evaluate a reviewed file artifact from the fixed capabilities.
    pub fn resume_file_read(
        &self,
        review: Box<ReadReview>,
        acceptance: Option<ReadAcceptance>,
    ) -> Result<ReadSessionDecision<TrustedFileEncArtifact<'a>>> {
        let review = *review;
        let operation = match &review.binding.operation {
            ReadOperationBinding::File(operation) => *operation,
            ReadOperationBinding::Kv(_) => return Err(target_changed("read operation changed")),
        };
        let source = review.source.clone();
        let artifact = self.load_verified_file(&source)?;
        review.validate_target(
            artifact.binding_digest()?,
            &ReadOperationBinding::File(operation),
        )?;
        self.evaluate_file(
            artifact,
            operation,
            review.allow_non_member,
            ReadEvaluationState {
                binding: review.binding,
                source,
                acceptance,
                accepted_non_member: review.accepted_non_member,
            },
        )
    }

    /// Load, verify, and evaluate a KV artifact through the fixed secrets directory.
    pub fn begin_kv_read(
        &self,
        name: &str,
        operation: KvReadOperation,
        allow_non_member: bool,
    ) -> Result<ReadSessionDecision<TrustedKvEncArtifact<'a>>> {
        let allow_non_member = allow_non_member && operation != KvReadOperation::Environment;
        let source = ReadSource::Kv {
            name: name.to_string(),
        };
        let artifact = self.load_verified_kv(&source)?;
        let binding = ReadReviewBinding::new(
            artifact.binding_digest(),
            ReadOperationBinding::Kv(operation.clone()),
        );
        self.evaluate_kv(
            artifact,
            operation,
            allow_non_member,
            ReadEvaluationState {
                binding,
                source,
                acceptance: None,
                accepted_non_member: None,
            },
        )
    }

    /// Re-evaluate a reviewed KV artifact from the fixed capabilities.
    pub fn resume_kv_read(
        &self,
        review: Box<ReadReview>,
        acceptance: Option<ReadAcceptance>,
    ) -> Result<ReadSessionDecision<TrustedKvEncArtifact<'a>>> {
        let review = *review;
        let operation = match &review.binding.operation {
            ReadOperationBinding::Kv(operation) => operation.clone(),
            ReadOperationBinding::File(_) => return Err(target_changed("read operation changed")),
        };
        let source = review.source.clone();
        let artifact = self.load_verified_kv(&source)?;
        review.validate_target(
            artifact.binding_digest(),
            &ReadOperationBinding::Kv(operation.clone()),
        )?;
        self.evaluate_kv(
            artifact,
            operation,
            review.allow_non_member,
            ReadEvaluationState {
                binding: review.binding,
                source,
                acceptance,
                accepted_non_member: review.accepted_non_member,
            },
        )
    }

    fn evaluate_file(
        &self,
        artifact: VerifiedFileEncArtifact,
        operation: FileReadOperation,
        allow_non_member: bool,
        state: ReadEvaluationState,
    ) -> Result<ReadSessionDecision<TrustedFileEncArtifact<'a>>> {
        let ReadEvaluationState {
            binding,
            source,
            acceptance,
            accepted_non_member,
        } = state;
        let evaluator = self.load_evaluator()?;
        let preflight = evaluator.preflight_file_read(
            &artifact,
            self.key_ctx,
            self.known_key_review,
            allow_non_member,
        )?;
        let resolved = resolve_exceptions(
            &preflight,
            &binding,
            acceptance,
            accepted_non_member,
            self.known_key_review,
        )?;
        if resolved.exceptions.is_none() {
            return review_or_continue(preflight, binding, allow_non_member, None, source);
        }
        let unresolved = preflight.unresolved_recipient_kids().to_vec();
        match evaluator.evaluate_file(
            &artifact,
            self.key_ctx,
            operation,
            self.options,
            resolved.exceptions.expect("resolved exception"),
        )? {
            TrustDecision::Trusted(_) => {
                TrustedFileEncArtifact::from_authorized_owned(artifact, self.key_ctx, self.options)
                    .map(|value| authorized(value, unresolved))
            }
            TrustDecision::ReviewRequired(_) => review_or_continue(
                preflight,
                binding,
                true,
                resolved.accepted_non_member,
                source,
            ),
        }
    }

    fn evaluate_kv(
        &self,
        artifact: VerifiedKvEncArtifact,
        operation: KvReadOperation,
        allow_non_member: bool,
        state: ReadEvaluationState,
    ) -> Result<ReadSessionDecision<TrustedKvEncArtifact<'a>>> {
        let ReadEvaluationState {
            binding,
            source,
            acceptance,
            accepted_non_member,
        } = state;
        let evaluator = self.load_evaluator()?;
        let preflight = evaluator.preflight_kv_read(
            &artifact,
            self.key_ctx,
            self.known_key_review,
            allow_non_member,
        )?;
        let resolved = resolve_exceptions(
            &preflight,
            &binding,
            acceptance,
            accepted_non_member,
            self.known_key_review,
        )?;
        if resolved.exceptions.is_none() {
            return review_or_continue(preflight, binding, allow_non_member, None, source);
        }
        let unresolved = preflight.unresolved_recipient_kids().to_vec();
        match evaluator.evaluate_kv(
            &artifact,
            self.key_ctx,
            operation.clone(),
            self.options,
            resolved.exceptions.expect("resolved exception"),
        )? {
            TrustDecision::Trusted(_) => TrustedKvEncArtifact::from_authorized_owned(
                artifact,
                self.key_ctx,
                operation,
                self.options,
            )
            .map(|value| authorized(value, unresolved)),
            TrustDecision::ReviewRequired(_) => review_or_continue(
                preflight,
                binding,
                true,
                resolved.accepted_non_member,
                source,
            ),
        }
    }

    fn load_verified_file(&self, source: &ReadSource) -> Result<VerifiedFileEncArtifact> {
        match source {
            ReadSource::File { file, source_name } => {
                let mut reader = file.try_clone().map_err(|error| {
                    Error::build_io_error_with_source("Failed to clone reviewed file", error)
                })?;
                reader.seek(SeekFrom::Start(0)).map_err(|error| {
                    Error::build_io_error_with_source("Failed to reread reviewed file", error)
                })?;
                FileEncArtifact::load_reader(reader, source_name.clone())?.verify(self.options)
            }
            ReadSource::Content { raw, source_name } => {
                FileEncArtifact::load_reader(raw.as_bytes(), source_name.clone())?
                    .verify(self.options)
            }
            ReadSource::Kv { .. } => Err(target_changed("file read source changed")),
        }
    }

    fn load_verified_kv(&self, source: &ReadSource) -> Result<VerifiedKvEncArtifact> {
        let ReadSource::Kv { name } = source else {
            return Err(target_changed("KV read source changed"));
        };
        self.load_kv_artifact(name)?.verify(self.options)
    }

    fn load_evaluator(&self) -> Result<TrustPolicyEvaluator> {
        let members = CurrentMemberSnapshot::load_at(&self.workspace)?;
        let Some(home) = self.home.as_ref() else {
            return Ok(TrustPolicyEvaluator::new(members, None));
        };
        let Some(trust_dir) = self.opened_trust_directory()? else {
            return Ok(TrustPolicyEvaluator::new(members, None));
        };
        let store =
            LocalTrustStore::open_from_anchored_base(home, self.key_ctx.member_handle().clone())
                .load_verified_at(trust_dir, self.key_ctx.inner().local_keystore_access())?
                .map(|loaded| loaded.into_store());
        Ok(TrustPolicyEvaluator::new(members, store))
    }

    pub(crate) fn opened_trust_directory(&self) -> Result<Option<&OpenDir>> {
        if let Some(trust_dir) = self.trust_dir.get() {
            return Ok(Some(trust_dir.as_ref()));
        }
        let Some(home) = self.home.as_ref() else {
            return Ok(None);
        };
        let Some(opened) = open_optional_child_dir(home, TRUST_DIR_NAME)? else {
            return Ok(None);
        };
        let _ = self.trust_dir.set(Arc::new(opened));
        Ok(self.trust_dir.get().map(Arc::as_ref))
    }

    pub(crate) fn local_state_home(&self) -> Option<&AnchoredDir> {
        self.home.as_ref()
    }

    pub(crate) fn member_handle(&self) -> &MemberHandle {
        self.key_ctx.member_handle()
    }

    pub(crate) fn cloned_trust_directory(&self) -> Result<Option<Arc<OpenDir>>> {
        let _ = self.opened_trust_directory()?;
        Ok(self.trust_dir.get().cloned())
    }

    fn ensured_trust_directory(&self) -> Result<&OpenDir> {
        if let Some(trust_dir) = self.trust_dir.get() {
            return Ok(trust_dir.as_ref());
        }
        let home = self.home.as_ref().ok_or_else(|| {
            Error::build_invalid_operation_error(
                "Local state is required to save trust approvals".to_string(),
            )
        })?;
        let opened =
            crate::support::fs::relative::ensure_child_dir_restricted_at(home, TRUST_DIR_NAME)?;
        Ok(self.trust_dir.get_or_init(|| Arc::new(opened)).as_ref())
    }
}

fn open_workspace_directories(path: &Path) -> Result<(AnchoredDir, Arc<OpenDir>)> {
    let workspace = AnchoredDir::open(
        path.to_path_buf(),
        DirectoryScope::Generic,
        "workspace root",
    )?;
    let secrets_dir = Arc::new(open_child_dir(&workspace, SECRETS_DIR_NAME)?);
    Ok((workspace, secrets_dir))
}

fn select_local_state_home(
    local_state_home: Option<AnchoredDir>,
    key_home: Option<AnchoredDir>,
) -> Result<Option<AnchoredDir>> {
    let (Some(local_state_home), Some(key_home)) = (&local_state_home, &key_home) else {
        return Ok(local_state_home.or(key_home));
    };
    if open_dir_identity(local_state_home)? != open_dir_identity(key_home)? {
        return Err(Error::build_invalid_operation_error(
            "Selected key belongs to a different local-state home".to_string(),
        ));
    }
    Ok(Some(local_state_home.clone()))
}

impl<T> AuthorizedRead<T> {
    /// Return the trust-authorized value.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Consume the result and return the trust-authorized value.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Return unresolved recipient key IDs collected during authorization.
    pub fn unresolved_recipient_kids(&self) -> &[Kid] {
        &self.unresolved_recipient_kids
    }
}

impl ReadReview {
    /// Return recipient trust requests that must be resolved before resuming.
    pub fn requests(&self) -> &[TrustReviewRequest] {
        &self.requests
    }

    /// Return whether the first key review request belongs to the artifact signer.
    pub fn first_request_is_signer(&self) -> bool {
        self.first_request_is_signer
    }

    /// Return the verified non-member signer review, when present.
    pub fn non_member_signer(&self) -> Option<&NonMemberReadReview> {
        self.non_member_signer.as_ref()
    }

    /// Return unresolved artifact recipient key IDs for display.
    pub fn unresolved_recipient_kids(&self) -> &[Kid] {
        &self.unresolved_recipient_kids
    }

    /// Mint a one-shot acceptance for the exact signer shown by this review.
    pub fn accept_non_member(&mut self) -> Result<ReadAcceptance> {
        if self.acceptance_issued {
            return Err(Error::build_invalid_operation_error(
                "The non-member signer review was already accepted".to_string(),
            ));
        }
        let signer = self
            .non_member_signer
            .as_ref()
            .ok_or_else(|| {
                Error::build_invalid_operation_error(
                    "This read review has no non-member signer".to_string(),
                )
            })?
            .identity();
        self.acceptance_issued = true;
        Ok(ReadAcceptance {
            review_id: self.binding.review_id,
            digest: self.binding.digest,
            operation: self.binding.operation.clone(),
            signer,
        })
    }

    fn validate_target(&self, digest: [u8; 32], operation: &ReadOperationBinding) -> Result<()> {
        if self.binding.digest == digest && &self.binding.operation == operation {
            Ok(())
        } else {
            Err(target_changed("reviewed read target changed"))
        }
    }
}

impl NonMemberReadReview {
    /// Return the cryptographically verified signer candidate.
    pub fn candidate(&self) -> &KnownKeyReviewCandidate {
        &self.candidate
    }

    /// Return display-only recipient handles captured from the artifact.
    pub fn recipient_handles(&self) -> &[MemberHandle] {
        &self.recipient_handles
    }

    fn identity(&self) -> (MemberHandle, Kid) {
        (
            self.candidate.subject_handle().clone(),
            self.candidate.kid().clone(),
        )
    }
}

impl ReadReviewBinding {
    fn new(digest: [u8; 32], operation: ReadOperationBinding) -> Self {
        Self {
            review_id: Uuid::new_v4(),
            digest,
            operation,
        }
    }
}

struct ResolvedExceptions {
    exceptions: Option<ReadTrustExceptions>,
    accepted_non_member: Option<AcceptedNonMember>,
}

fn resolve_exceptions(
    preflight: &ReadTrustReview,
    binding: &ReadReviewBinding,
    acceptance: Option<ReadAcceptance>,
    accepted_non_member: Option<AcceptedNonMember>,
    known_key_review: KnownKeyReview,
) -> Result<ResolvedExceptions> {
    let accepted = match (acceptance, accepted_non_member) {
        (Some(acceptance), None) => Some(AcceptedNonMember::from(acceptance)),
        (None, accepted) => accepted,
        (Some(_), Some(_)) => {
            return Err(target_changed("non-member acceptance was reused"));
        }
    };
    let Some(accepted) = accepted else {
        if preflight.non_member_signer().is_some() || !preflight.requests().is_empty() {
            return Ok(ResolvedExceptions {
                exceptions: None,
                accepted_non_member: None,
            });
        }
        return Ok(ResolvedExceptions {
            exceptions: Some(ReadTrustExceptions::none().with_known_key_review(known_key_review)),
            accepted_non_member: None,
        });
    };
    validate_acceptance(preflight, binding, &accepted)?;
    let signer = accepted.signer.clone();
    Ok(ResolvedExceptions {
        exceptions: Some(
            ReadTrustExceptions::none()
                .with_known_key_review(known_key_review)
                .accepting_non_member(signer.0, signer.1),
        ),
        accepted_non_member: Some(accepted),
    })
}

fn validate_acceptance(
    preflight: &ReadTrustReview,
    binding: &ReadReviewBinding,
    acceptance: &AcceptedNonMember,
) -> Result<()> {
    let Some(non_member) = preflight.non_member_signer() else {
        return Err(target_changed("reviewed signer trust changed"));
    };
    let identity = (
        non_member.candidate().subject_handle().clone(),
        non_member.candidate().kid().clone(),
    );
    if acceptance.review_id == binding.review_id
        && acceptance.digest == binding.digest
        && acceptance.operation == binding.operation
        && acceptance.signer == identity
    {
        Ok(())
    } else {
        Err(target_changed("reviewed signer or read target changed"))
    }
}

impl From<ReadAcceptance> for AcceptedNonMember {
    fn from(acceptance: ReadAcceptance) -> Self {
        Self {
            review_id: acceptance.review_id,
            digest: acceptance.digest,
            operation: acceptance.operation,
            signer: acceptance.signer,
        }
    }
}

fn review_or_continue<T>(
    preflight: ReadTrustReview,
    binding: ReadReviewBinding,
    allow_non_member: bool,
    accepted_non_member: Option<AcceptedNonMember>,
    source: ReadSource,
) -> Result<ReadSessionDecision<T>> {
    if preflight.requests().is_empty()
        && (preflight.non_member_signer().is_none() || accepted_non_member.is_some())
    {
        preflight.into_recipient_requests()?;
        return Err(Error::build_invalid_operation_error(
            "Read authorization did not produce a capability".to_string(),
        ));
    }
    Ok(ReadSessionDecision::ReviewRequired(Box::new(read_review(
        &preflight,
        binding,
        allow_non_member,
        accepted_non_member,
        source,
    ))))
}

fn read_review(
    preflight: &ReadTrustReview,
    binding: ReadReviewBinding,
    allow_non_member: bool,
    accepted_non_member: Option<AcceptedNonMember>,
    source: ReadSource,
) -> ReadReview {
    let signer_pending = accepted_non_member.is_none() && preflight.non_member_signer().is_some();
    ReadReview {
        binding,
        requests: if signer_pending {
            Vec::new()
        } else {
            preflight.requests().to_vec()
        },
        first_request_is_signer: !signer_pending && preflight.first_request_is_signer(),
        non_member_signer: if accepted_non_member.is_none() {
            preflight.non_member_signer().map(public_non_member_review)
        } else {
            None
        },
        unresolved_recipient_kids: preflight.unresolved_recipient_kids().to_vec(),
        allow_non_member,
        acceptance_issued: false,
        accepted_non_member,
        source,
    }
}

fn public_non_member_review(review: &NonMemberSignerReview) -> NonMemberReadReview {
    NonMemberReadReview {
        candidate: review.candidate().clone(),
        recipient_handles: review.recipient_handles().to_vec(),
    }
}

fn authorized<T>(value: T, unresolved: Vec<Kid>) -> ReadSessionDecision<T> {
    ReadSessionDecision::Authorized(AuthorizedRead {
        value,
        unresolved_recipient_kids: unresolved,
    })
}

fn target_changed(message: &str) -> Error {
    Error::build_verification_error("E_TRUST_TARGET_CHANGED", message)
}
