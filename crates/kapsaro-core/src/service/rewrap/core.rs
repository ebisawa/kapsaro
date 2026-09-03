// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Core operation-bound rewrap capability for verified file and KV artifacts.
//! Only trust policy evaluation can construct the capability that reaches rewrite code.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use crate::feature::rewrap::{rewrap_content, RewrapRequest};
use crate::format::content::EncContent;
use crate::io::trust::paths::TRUST_DIR_NAME;
use crate::io::workspace::setup::SECRETS_DIR_NAME;
use crate::service::artifact::ReviewedTextFile;
use crate::service::file::{FileEncArtifact, VerifiedFileEncArtifact};
use crate::service::key::{KeyContext, Kid, MemberHandle, RecipientKeys};
use crate::service::kv::VerifiedKvEncArtifact;
use crate::service::operation::OperationOptions;
use crate::service::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, KnownKeyReview, KnownKeyReviewCandidate,
    LocalTrustStore, NonMemberSignerReview, RecipientSetSubject, TrustApproval,
    TrustApprovalOutcome, TrustCommandSession, TrustDecision, TrustPolicyEvaluator,
    TrustReviewRequest,
};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock;
use crate::support::fs::relative::{
    duplicate_open_dir, ensure_child_dir_restricted_at, open_child_dir, open_dir_identity,
    open_dir_nofollow, open_optional_child_dir, open_os_child_dir_nofollow, regular_file_exists_at,
    DirectoryFd, DirectoryScope, EntryIdentity, OpenDir,
};
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use uuid::Uuid;

/// Rewrap behavior bound into one authorization decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RewrapOptions {
    rotate_key: bool,
    clear_disclosure_history: bool,
    operation: OperationOptions,
}

impl RewrapOptions {
    /// Build fail-closed rewrap options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rotate the artifact content key while rewrapping.
    pub fn with_rotate_key(mut self, rotate_key: bool) -> Self {
        self.rotate_key = rotate_key;
        self
    }

    /// Remove disclosure history while rewrapping.
    pub fn with_clear_disclosure_history(mut self, clear: bool) -> Self {
        self.clear_disclosure_history = clear;
        self
    }

    /// Apply common key-expiration behavior.
    pub fn with_operation_options(mut self, operation: OperationOptions) -> Self {
        self.operation = operation;
        self
    }

    pub(crate) fn operation_options(self) -> OperationOptions {
        self.operation
    }
}

enum AuthorizedArtifact {
    File(VerifiedFileEncArtifact),
    Kv(VerifiedKvEncArtifact),
}

/// Trust-authorized rewrap input bound to artifact, recipients, key, and options.
pub struct AuthorizedRewrapInput<'a> {
    artifact: AuthorizedArtifact,
    recipients: RecipientKeys,
    key_ctx: &'a KeyContext,
    options: RewrapOptions,
    publish_target: Option<RewrapPublishTarget>,
}

/// Result of a fixed-session rewrap authorization attempt.
pub enum RewrapSessionDecision<T> {
    Authorized(T),
    ReviewRequired(Box<RewrapReview>),
}

/// Opaque review state bound to one artifact and exact rewrap options.
pub struct RewrapReview {
    target: RewrapTarget,
    digest: [u8; 32],
    operation: RewrapOperationBinding,
    requests: Vec<TrustReviewRequest>,
    first_request_is_signer: bool,
    non_member: Option<RewrapNonMemberReview>,
    accepted_non_member: Option<RewrapAcceptance>,
    reviewed: ReviewedTextFile,
    input_state: TrustPolicyEvaluator,
    post_promotion_members: Option<CurrentMemberSnapshot>,
}

/// Fixed workspace and local-state capabilities for pre/post rewrap evaluation.
pub struct RewrapSession<'a> {
    workspace: AnchoredDir,
    workspace_capability: Arc<OpenDir>,
    secrets_dir: Arc<OpenDir>,
    home: Option<AnchoredDir>,
    trust_dir: OnceLock<Arc<OpenDir>>,
    key_ctx: &'a KeyContext,
    trust_session: Option<&'a TrustCommandSession>,
    pre_promotion_members: CurrentMemberSnapshot,
    post_promotion_snapshot: Mutex<Option<super::snapshot::PostPromotionSnapshot>>,
}

/// Fixed directory capabilities required by one rewrap session.
pub struct RewrapDirectories {
    workspace: AnchoredDir,
    workspace_capability: Arc<OpenDir>,
    secrets_dir: Arc<OpenDir>,
    home: Option<AnchoredDir>,
}

/// Workspace artifact targets and discovery warnings from one fixed directory.
pub struct RewrapTargetListing {
    targets: Vec<RewrapTarget>,
    warnings: Vec<String>,
}

/// Incoming member review bound to snapshots held by the fixed session.
pub struct RewrapPromotionReview {
    session: super::promotion::PromotionReviewSession,
}

/// Result of applying reviewed incoming-member promotions.
pub struct RewrapPromotionOutcome {
    promoted_member_handles: Vec<String>,
    trust_outcome: Option<TrustApprovalOutcome>,
}

/// One rewrap target fixed to the directory capability used for review.
pub struct RewrapTarget {
    dir: Arc<OpenDir>,
    parent_binding: RewrapParentBinding,
    parent_identity: EntryIdentity,
    name: String,
    display_path: PathBuf,
}

enum RewrapParentBinding {
    Root,
    Child {
        ancestor: Arc<OpenDir>,
        name: OsString,
    },
}

impl PartialEq for RewrapTarget {
    fn eq(&self, other: &Self) -> bool {
        self.as_selection_key() == other.as_selection_key()
    }
}

impl Eq for RewrapTarget {}

impl PartialOrd for RewrapTarget {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RewrapTarget {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_selection_key().cmp(&other.as_selection_key())
    }
}

struct RewrapPublishTarget {
    target: RewrapTarget,
    reviewed: ReviewedTextFile,
}

enum PreparedRewrapReview {
    Ready(Box<(RewrapTarget, ReviewedTextFile)>),
    Review(Box<RewrapReview>),
}

struct RewrapReviewInput {
    target: RewrapTarget,
    digest: [u8; 32],
    operation: RewrapOperationBinding,
    input_state: TrustPolicyEvaluator,
    input_review: crate::service::trust::ReadTrustReview,
    reviewed: ReviewedTextFile,
}

/// Opaque review state for the exact verified non-member rewrap signer.
pub struct RewrapNonMemberReview {
    review_id: Uuid,
    digest: [u8; 32],
    operation: RewrapOperationBinding,
    signer: (MemberHandle, Kid),
    candidate: KnownKeyReviewCandidate,
    recipient_handles: Vec<MemberHandle>,
    acceptance_issued: bool,
}

/// One-shot acceptance minted only from verified rewrap review state.
pub struct RewrapAcceptance {
    review_id: Uuid,
    digest: [u8; 32],
    operation: RewrapOperationBinding,
    signer: (MemberHandle, Kid),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RewrapArtifactKind {
    File,
    Kv,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RewrapOperationBinding {
    artifact_kind: RewrapArtifactKind,
    options: RewrapOptions,
}

impl<'a> AuthorizedRewrapInput<'a> {
    pub(crate) fn from_file(
        artifact: VerifiedFileEncArtifact,
        recipients: RecipientKeys,
        key_ctx: &'a KeyContext,
        options: RewrapOptions,
    ) -> Result<Self> {
        key_ctx.enforce_decryption_key_not_expired(
            &artifact.inner().document().protected.wrap,
            options.operation_options(),
        )?;
        key_ctx.inner().enforce_signing_key_not_expired()?;
        crate::feature::envelope::key_possession::verify_file_key_possession(
            artifact.inner(),
            crate::feature::envelope::unwrap::unwrap_master_key_for_file_with_context(
                artifact.inner(),
                key_ctx.member_handle(),
                key_ctx.inner(),
            )?
            .value,
        )?;
        Ok(Self {
            artifact: AuthorizedArtifact::File(artifact),
            recipients,
            key_ctx,
            options,
            publish_target: None,
        })
    }

    pub(crate) fn from_kv(
        artifact: VerifiedKvEncArtifact,
        recipients: RecipientKeys,
        key_ctx: &'a KeyContext,
        options: RewrapOptions,
    ) -> Result<Self> {
        let document = artifact.inner().document();
        key_ctx.enforce_decryption_key_not_expired(
            &document.wrap().wrap,
            options.operation_options(),
        )?;
        key_ctx.inner().enforce_signing_key_not_expired()?;
        crate::feature::envelope::key_possession::verify_kv_key_possession(
            artifact.inner(),
            crate::feature::envelope::unwrap::unwrap_master_key_for_kv_with_context(
                &document.head().sid,
                &document.wrap().wrap,
                key_ctx.member_handle(),
                key_ctx.inner(),
            )?
            .value,
        )?;
        Ok(Self {
            artifact: AuthorizedArtifact::Kv(artifact),
            recipients,
            key_ctx,
            options,
            publish_target: None,
        })
    }

    /// Rewrite the exact artifact and recipient set authorized by trust policy.
    pub fn rewrite(&self) -> Result<String> {
        let content = match &self.artifact {
            AuthorizedArtifact::File(artifact) => EncContent::FileEnc(artifact.content().clone()),
            AuthorizedArtifact::Kv(artifact) => EncContent::KvEnc(artifact.content().clone()),
        };
        rewrap_content(
            &content,
            &RewrapRequest {
                member_handle: self.key_ctx.member_handle().as_str(),
                key_ctx: self.key_ctx.inner(),
                target_members: self.recipients.keys().to_vec(),
                rotate_key: self.options.rotate_key,
                clear_disclosure_history: self.options.clear_disclosure_history,
            },
        )
    }

    /// Rewrite and atomically publish through the reviewed filesystem capability.
    pub fn publish(self) -> Result<()> {
        let rewritten = self.rewrite()?;
        let target = self.publish_target.ok_or_else(|| {
            crate::Error::build_invalid_operation_error(
                "This rewrap authorization has no publish target".to_string(),
            )
        })?;
        target.publish(&rewritten)
    }

    fn with_publish_target(mut self, target: RewrapPublishTarget) -> Self {
        self.publish_target = Some(target);
        self
    }
}

impl RewrapTarget {
    /// Identify the directory entry that an atomic replacement will publish.
    /// Distinct hardlink names remain distinct because replacing one breaks that link.
    fn as_selection_key(&self) -> (&EntryIdentity, &str) {
        (&self.parent_identity, &self.name)
    }

    /// Fix an explicitly selected artifact below its opened parent directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let display_path = path.to_path_buf();
        let absolute = std::path::absolute(path).map_err(|error| {
            Error::build_io_error_with_source(
                format!("Failed to resolve artifact target: {}", path.display()),
                error,
            )
        })?;
        let name = target_file_name(&absolute)?;
        let parent_path = absolute
            .parent()
            .ok_or_else(|| invalid_target_parent(path))?;
        let dir = Arc::new(open_dir_nofollow(parent_path, DirectoryScope::Generic)?);
        let parent_identity = open_dir_identity(dir.as_ref())?;
        let parent_binding = resolve_rewrap_parent_binding(parent_path, &parent_identity)?;
        Self::from_fixed_parent(parent_binding, dir, name, display_path)
    }

    pub(crate) fn from_capabilities(
        parent: Arc<OpenDir>,
        parent_child_name: &str,
        dir: Arc<OpenDir>,
        name: String,
        display_path: PathBuf,
    ) -> Result<Self> {
        let parent_binding = RewrapParentBinding::Child {
            ancestor: parent,
            name: OsString::from(parent_child_name),
        };
        Self::from_fixed_parent(parent_binding, dir, name, display_path)
    }

    fn from_fixed_parent(
        parent_binding: RewrapParentBinding,
        dir: Arc<OpenDir>,
        name: String,
        display_path: PathBuf,
    ) -> Result<Self> {
        let parent_identity = open_dir_identity(dir.as_ref())?;
        if !regular_file_exists_at(dir.as_ref(), &name)? {
            return Err(Error::build_not_found_error(format!(
                "Failed to read file {}: no such file",
                format_path_relative_to_cwd(&display_path)
            )));
        }
        Ok(Self {
            parent_binding,
            parent_identity,
            dir,
            name,
            display_path,
        })
    }

    /// Return the target entry name fixed below its directory capability.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the caller-facing path without re-resolving it.
    pub fn path(&self) -> &Path {
        &self.display_path
    }

    fn review(&self) -> Result<ReviewedTextFile> {
        ReviewedTextFile::load_existing_at(
            Arc::clone(&self.dir),
            &self.name,
            "encrypted artifact",
            resolve_encrypted_artifact_read_limit(Path::new(&self.name)),
        )
    }

    fn artifact_kind(&self) -> Result<RewrapArtifactKind> {
        match crate::service::artifact::detect_reviewed_artifact(&self.review()?)? {
            EncContent::FileEnc(_) => Ok(RewrapArtifactKind::File),
            EncContent::KvEnc(_) => Ok(RewrapArtifactKind::Kv),
        }
    }

    fn ensure_parent_current(&self) -> Result<()> {
        let RewrapParentBinding::Child { ancestor, name } = &self.parent_binding else {
            return Ok(());
        };
        let current = open_os_child_dir_nofollow(ancestor.as_ref(), name)
            .map_err(|_| target_changed_error())?;
        if open_dir_identity(&current)? == self.parent_identity {
            return Ok(());
        }
        Err(target_changed_error())
    }
}

fn resolve_rewrap_parent_binding(
    parent_path: &Path,
    expected_identity: &EntryIdentity,
) -> Result<RewrapParentBinding> {
    let canonical_parent = parent_path
        .canonicalize()
        .map_err(|_| target_changed_error())?;
    let Some(name) = canonical_parent.file_name() else {
        let current = open_dir_nofollow(&canonical_parent, DirectoryScope::Generic)
            .map_err(|_| target_changed_error())?;
        if open_dir_identity(&current)? != *expected_identity {
            return Err(target_changed_error());
        }
        return Ok(RewrapParentBinding::Root);
    };
    let ancestor_path = canonical_parent
        .parent()
        .ok_or_else(|| invalid_target_parent(&canonical_parent))?;
    let ancestor = Arc::new(open_dir_nofollow(ancestor_path, DirectoryScope::Generic)?);
    let current =
        open_os_child_dir_nofollow(ancestor.as_ref(), name).map_err(|_| target_changed_error())?;
    if open_dir_identity(&current)? != *expected_identity {
        return Err(target_changed_error());
    }
    Ok(RewrapParentBinding::Child {
        ancestor,
        name: name.to_os_string(),
    })
}

impl RewrapPublishTarget {
    fn new(target: RewrapTarget, reviewed: ReviewedTextFile) -> Self {
        Self { target, reviewed }
    }

    fn publish(self, rewritten: &str) -> Result<()> {
        lock::with_exclusive_locked_directory(self.target.dir.as_ref(), |locked_dir| {
            self.reviewed
                .save_replacement_if_current_with_precondition_at(locked_dir, rewritten, || {
                    self.target.ensure_parent_current()
                })
        })
    }
}

fn target_file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| {
            Error::build_invalid_argument_error(format!(
                "Artifact target names no UTF-8 file: {}",
                format_path_relative_to_cwd(path)
            ))
        })
}

fn invalid_target_parent(path: &Path) -> Error {
    Error::build_invalid_argument_error(format!(
        "Artifact parent cannot be fixed below an ancestor: {}",
        format_path_relative_to_cwd(path)
    ))
}

fn target_changed_error() -> Error {
    Error::build_verification_error(
        "E_TRUST_TARGET_CHANGED".to_string(),
        "Rewrap target or trust state changed after review. Run the command again.".to_string(),
    )
}

impl RewrapDirectories {
    pub(crate) fn from_fixed(
        workspace: AnchoredDir,
        secrets_dir: Arc<OpenDir>,
        home: Option<AnchoredDir>,
    ) -> Result<Self> {
        let workspace_capability = Arc::new(duplicate_open_dir(&workspace)?);
        Ok(Self {
            workspace,
            workspace_capability,
            secrets_dir,
            home,
        })
    }
}

impl RewrapTargetListing {
    /// Return warnings for artifact-shaped entries that could not be fixed.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Consume the listing and return its fixed artifact targets.
    pub fn into_targets(self) -> Vec<RewrapTarget> {
        self.targets
    }

    /// Return whether the fixed workspace contained no eligible artifact.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

impl RewrapPromotionReview {
    /// Return semantic promotion review data for caller presentation.
    pub fn view(&self) -> &super::promotion::PromotionReviewView {
        self.session.view()
    }
}

impl RewrapPromotionOutcome {
    /// Return the incoming members promoted through the fixed workspace.
    pub fn promoted_member_handles(&self) -> &[String] {
        &self.promoted_member_handles
    }

    /// Return diagnostics from persisting promotion trust approvals.
    pub fn trust_outcome(&self) -> Option<&TrustApprovalOutcome> {
        self.trust_outcome.as_ref()
    }
}

impl<'a> RewrapSession<'a> {
    /// Fix the workspace and local-state roots and capture pre-promotion members.
    pub fn open(
        workspace_path: impl AsRef<Path>,
        home_path: Option<PathBuf>,
        key_ctx: &'a KeyContext,
    ) -> Result<Self> {
        let workspace = AnchoredDir::open(
            workspace_path.as_ref().to_path_buf(),
            DirectoryScope::Generic,
            "workspace root",
        )?;
        let secrets_dir = Arc::new(open_child_dir(&workspace, SECRETS_DIR_NAME)?);
        let home = home_path
            .map(|path| AnchoredDir::open(path, DirectoryScope::LocalState, "local state root"))
            .transpose()?;
        Self::from_directories(
            RewrapDirectories::from_fixed(workspace, secrets_dir, home)?,
            key_ctx,
        )
    }

    /// Bind rewrap and trust-store recovery to one fixed trust command session.
    pub fn from_trust_command(
        workspace_path: impl AsRef<Path>,
        trust_session: &'a TrustCommandSession,
    ) -> Result<Self> {
        let workspace = AnchoredDir::open(
            workspace_path.as_ref().to_path_buf(),
            DirectoryScope::Generic,
            "workspace root",
        )?;
        let secrets_dir = Arc::new(open_child_dir(&workspace, SECRETS_DIR_NAME)?);
        let directories = RewrapDirectories::from_fixed(
            workspace,
            secrets_dir,
            Some(trust_session.home().clone()),
        )?;
        let mut session = Self::from_directories(directories, trust_session.key_ctx())?;
        session.trust_session = Some(trust_session);
        Ok(session)
    }

    /// Bind already-fixed directory capabilities to one rewrap operation.
    pub fn from_directories(
        directories: RewrapDirectories,
        key_ctx: &'a KeyContext,
    ) -> Result<Self> {
        let pre_promotion_members = CurrentMemberSnapshot::load_at(&directories.workspace)?;
        Ok(Self {
            workspace: directories.workspace,
            workspace_capability: directories.workspace_capability,
            secrets_dir: directories.secrets_dir,
            home: directories.home,
            trust_dir: OnceLock::new(),
            key_ctx,
            trust_session: None,
            pre_promotion_members,
            post_promotion_snapshot: Mutex::new(None),
        })
    }

    /// Return warnings for the fixed signing key used by this rewrap session.
    pub fn signing_key_warnings(&self) -> Result<Vec<String>> {
        Ok(self
            .key_ctx
            .inner()
            .build_signing_key_expiry_warning()?
            .into_iter()
            .collect())
    }

    /// Load a file artifact through the secrets directory fixed by this session.
    pub fn load_file_artifact(&self, name: &str) -> Result<FileEncArtifact> {
        FileEncArtifact::load_at(self.secrets_dir.as_ref(), name)
    }

    /// Load a KV artifact through the secrets directory fixed by this session.
    pub fn load_kv_artifact(&self, name: &str) -> Result<crate::service::kv::KvEncArtifact> {
        crate::service::kv::KvEncArtifact::load_at(self.secrets_dir.as_ref(), name)
    }

    /// Fix a workspace `secrets/` artifact below this session's capabilities.
    pub fn workspace_target(&self, name: &str) -> Result<RewrapTarget> {
        RewrapTarget::from_capabilities(
            Arc::clone(&self.workspace_capability),
            SECRETS_DIR_NAME,
            Arc::clone(&self.secrets_dir),
            name.to_string(),
            self.secrets_dir.path().join(name),
        )
    }

    /// List encrypted artifacts below the fixed workspace secrets directory.
    pub fn list_workspace_targets(&self) -> Result<RewrapTargetListing> {
        let listing =
            crate::service::artifact::list_workspace_encrypted_artifacts_at(&self.workspace)?;
        let targets = listing
            .artifacts
            .iter()
            .map(crate::service::artifact::ArtifactRef::rewrap_target)
            .collect::<Result<Vec<_>>>()?;
        Ok(RewrapTargetListing {
            targets,
            warnings: listing.warnings,
        })
    }

    /// Return expiry warnings for the current post-promotion recipient keys.
    pub fn post_promotion_warnings(&self) -> Result<Vec<String>> {
        let snapshot = self.ensure_post_promotion_snapshot()?;
        crate::feature::context::expiry::collect_recipient_key_expiry_warnings(
            snapshot.recipients().keys(),
        )
    }

    /// Build an incoming-member review without invoking caller callbacks.
    pub fn begin_promotion_review(
        &self,
        review_available: bool,
    ) -> Result<Option<RewrapPromotionReview>> {
        let Some(report) = super::plan::load_incoming_report_at(&self.workspace)? else {
            self.ensure_post_promotion_snapshot()?;
            return Ok(None);
        };
        let evaluator = self.load_input_evaluator()?;
        let self_trust = evaluator.self_trust(self.key_ctx)?;
        let plan = super::promotion::build_promotion_review_plan(
            &report,
            evaluator.known_keys(),
            &self_trust,
            review_available,
        )?;
        Ok(Some(RewrapPromotionReview {
            session: super::promotion::build_promotion_review_session(&plan)?,
        }))
    }

    /// Apply only the incoming promotions accepted from this session's review.
    pub fn apply_promotions(
        &self,
        review: RewrapPromotionReview,
        accepted_member_handles: &[String],
    ) -> Result<RewrapPromotionOutcome> {
        self.key_ctx.inner().enforce_signing_key_not_expired()?;
        let (candidates, approvals) = review
            .session
            .into_accepted_candidates_and_approvals(accepted_member_handles)?;
        let promoted_member_handles =
            super::snapshot::promote_accepted_incoming_members(&self.workspace, &candidates)?;
        self.ensure_post_promotion_snapshot()?;
        let trust_outcome = if approvals.is_empty() {
            None
        } else {
            Some(self.apply_approvals(approvals)?)
        };
        Ok(RewrapPromotionOutcome {
            promoted_member_handles,
            trust_outcome,
        })
    }

    /// Persist caller-approved trust requests through this session's fixed home.
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

    /// Persist one request approval and advance the opaque review to that state.
    pub fn apply_review_approval(
        &self,
        review: &mut RewrapReview,
        approval: TrustApproval,
    ) -> Result<TrustApprovalOutcome> {
        let outcome = self.apply_approvals(vec![approval])?;
        review.input_state = self.load_input_evaluator()?;
        Ok(outcome)
    }

    /// Begin authorization after detecting the artifact through the fixed target.
    pub fn begin_rewrap<'s>(
        &'s self,
        target: RewrapTarget,
        options: RewrapOptions,
        allow_non_member: bool,
    ) -> Result<RewrapSessionDecision<AuthorizedRewrapInput<'s>>> {
        match target.artifact_kind()? {
            RewrapArtifactKind::File => self.begin_file_rewrap(target, options, allow_non_member),
            RewrapArtifactKind::Kv => self.begin_kv_rewrap(target, options, allow_non_member),
        }
    }

    /// Resume authorization using the artifact kind bound into the opaque review.
    pub fn resume_rewrap<'s>(
        &'s self,
        review: Box<RewrapReview>,
        options: RewrapOptions,
        acceptance: Option<RewrapAcceptance>,
    ) -> Result<RewrapSessionDecision<AuthorizedRewrapInput<'s>>> {
        match review.operation.artifact_kind {
            RewrapArtifactKind::File => self.resume_file_rewrap(review, options, acceptance),
            RewrapArtifactKind::Kv => self.resume_kv_rewrap(review, options, acceptance),
        }
    }

    /// Begin file rewrap authorization from the session's fixed snapshots.
    pub fn begin_file_rewrap<'s>(
        &'s self,
        target: RewrapTarget,
        options: RewrapOptions,
        allow_non_member: bool,
    ) -> Result<RewrapSessionDecision<AuthorizedRewrapInput<'s>>> {
        self.ensure_post_promotion_snapshot()?;
        let reviewed = target.review()?;
        let artifact = FileEncArtifact::parse(reviewed.require_content()?.to_string())?
            .verify(options.operation_options())?;
        let digest = artifact.binding_digest()?;
        let operation = RewrapOperationBinding {
            artifact_kind: RewrapArtifactKind::File,
            options,
        };
        let input = self.load_input_evaluator()?;
        let subject = artifact.recipient_set_subject()?;
        let review = input.preflight_file_read(
            &artifact,
            self.key_ctx,
            KnownKeyReview::Required,
            allow_non_member,
        )?;
        let prepared = self.build_review(
            RewrapReviewInput {
                target,
                digest,
                operation,
                input_state: input,
                input_review: review,
                reviewed,
            },
            &subject,
        )?;
        let (target, reviewed) = match prepared {
            PreparedRewrapReview::Ready(ready) => *ready,
            PreparedRewrapReview::Review(review) => {
                return Ok(RewrapSessionDecision::ReviewRequired(review));
            }
        };
        let (input, output, recipients, members) = self.load_evaluators_and_recipients()?;
        let decision = output.evaluate_file_rewrap(
            &input,
            artifact,
            recipients,
            self.key_ctx,
            options,
            None,
        )?;
        into_session_decision(
            decision,
            digest,
            operation,
            None,
            RewrapPublishTarget::new(target, reviewed),
            input,
            members,
        )
    }

    /// Resume file authorization after persisting reviews and optional acceptance.
    pub fn resume_file_rewrap<'s>(
        &'s self,
        review: Box<RewrapReview>,
        options: RewrapOptions,
        acceptance: Option<RewrapAcceptance>,
    ) -> Result<RewrapSessionDecision<AuthorizedRewrapInput<'s>>> {
        let review = *review;
        review
            .reviewed
            .ensure_identity_and_content_current_at(review.target.dir.as_ref())?;
        let artifact = FileEncArtifact::parse(review.reviewed.require_content()?.to_string())?
            .verify(options.operation_options())?;
        let digest = artifact.binding_digest()?;
        let operation = RewrapOperationBinding {
            artifact_kind: RewrapArtifactKind::File,
            options,
        };
        review.validate(digest, operation)?;
        let (input, output, recipients, members) = self.load_evaluators_and_recipients()?;
        let live_members = CurrentMemberSnapshot::load_at(&self.workspace)?;
        review.validate_state(&input, &live_members)?;
        let expected_review_id = review.expected_acceptance_review_id();
        let acceptance =
            resolve_session_acceptance(acceptance, review.accepted_non_member, expected_review_id)?;
        let retained_acceptance = acceptance.as_ref().map(RewrapAcceptance::duplicate);
        let target = review.target;
        let reviewed = review.reviewed;
        let decision = output.evaluate_file_rewrap(
            &input,
            artifact,
            recipients,
            self.key_ctx,
            options,
            acceptance,
        )?;
        into_session_decision(
            decision,
            digest,
            operation,
            retained_acceptance,
            RewrapPublishTarget::new(target, reviewed),
            input,
            members,
        )
    }

    /// Begin KV rewrap authorization from the session's fixed snapshots.
    pub fn begin_kv_rewrap<'s>(
        &'s self,
        target: RewrapTarget,
        options: RewrapOptions,
        allow_non_member: bool,
    ) -> Result<RewrapSessionDecision<AuthorizedRewrapInput<'s>>> {
        self.ensure_post_promotion_snapshot()?;
        let reviewed = target.review()?;
        let artifact =
            crate::service::kv::KvEncArtifact::parse(reviewed.require_content()?.to_string())?
                .verify(options.operation_options())?;
        let digest = artifact.binding_digest();
        let operation = RewrapOperationBinding {
            artifact_kind: RewrapArtifactKind::Kv,
            options,
        };
        let input = self.load_input_evaluator()?;
        let subject = artifact.recipient_set_subject()?;
        let review = input.preflight_kv_read(
            &artifact,
            self.key_ctx,
            KnownKeyReview::Required,
            allow_non_member,
        )?;
        let prepared = self.build_review(
            RewrapReviewInput {
                target,
                digest,
                operation,
                input_state: input,
                input_review: review,
                reviewed,
            },
            &subject,
        )?;
        let (target, reviewed) = match prepared {
            PreparedRewrapReview::Ready(ready) => *ready,
            PreparedRewrapReview::Review(review) => {
                return Ok(RewrapSessionDecision::ReviewRequired(review));
            }
        };
        let (input, output, recipients, members) = self.load_evaluators_and_recipients()?;
        let decision =
            output.evaluate_kv_rewrap(&input, artifact, recipients, self.key_ctx, options, None)?;
        into_session_decision(
            decision,
            digest,
            operation,
            None,
            RewrapPublishTarget::new(target, reviewed),
            input,
            members,
        )
    }

    /// Resume KV authorization after persisting reviews and optional acceptance.
    pub fn resume_kv_rewrap<'s>(
        &'s self,
        review: Box<RewrapReview>,
        options: RewrapOptions,
        acceptance: Option<RewrapAcceptance>,
    ) -> Result<RewrapSessionDecision<AuthorizedRewrapInput<'s>>> {
        let review = *review;
        review
            .reviewed
            .ensure_identity_and_content_current_at(review.target.dir.as_ref())?;
        let artifact = crate::service::kv::KvEncArtifact::parse(
            review.reviewed.require_content()?.to_string(),
        )?
        .verify(options.operation_options())?;
        let digest = artifact.binding_digest();
        let operation = RewrapOperationBinding {
            artifact_kind: RewrapArtifactKind::Kv,
            options,
        };
        review.validate(digest, operation)?;
        let (input, output, recipients, members) = self.load_evaluators_and_recipients()?;
        let live_members = CurrentMemberSnapshot::load_at(&self.workspace)?;
        review.validate_state(&input, &live_members)?;
        let expected_review_id = review.expected_acceptance_review_id();
        let acceptance =
            resolve_session_acceptance(acceptance, review.accepted_non_member, expected_review_id)?;
        let retained_acceptance = acceptance.as_ref().map(RewrapAcceptance::duplicate);
        let target = review.target;
        let reviewed = review.reviewed;
        let decision = output.evaluate_kv_rewrap(
            &input,
            artifact,
            recipients,
            self.key_ctx,
            options,
            acceptance,
        )?;
        into_session_decision(
            decision,
            digest,
            operation,
            retained_acceptance,
            RewrapPublishTarget::new(target, reviewed),
            input,
            members,
        )
    }

    fn build_review(
        &self,
        input: RewrapReviewInput,
        subject: &RecipientSetSubject,
    ) -> Result<PreparedRewrapReview> {
        let RewrapReviewInput {
            target,
            digest,
            operation,
            input_state,
            input_review,
            reviewed,
        } = input;
        let first_request_is_signer = input_review.first_request_is_signer();
        let non_member = input_review.non_member_signer().map(|review| {
            RewrapNonMemberReview::from_verified(
                digest,
                operation.artifact_kind,
                operation.options,
                review,
            )
        });
        if non_member.is_some() {
            let post_promotion_members = self.ensure_post_promotion_snapshot()?.members().clone();
            return Ok(PreparedRewrapReview::Review(Box::new(RewrapReview {
                target,
                digest,
                operation,
                requests: Vec::new(),
                first_request_is_signer: false,
                non_member,
                accepted_non_member: None,
                reviewed,
                input_state,
                post_promotion_members: Some(post_promotion_members),
            })));
        }
        let mut requests = input_review.into_recipient_requests()?;
        let (_, output, recipients, members) = self.load_evaluators_and_recipients()?;
        requests.extend(output.preflight_rewrap_output(subject, &recipients, self.key_ctx)?);
        if requests.is_empty() && non_member.is_none() {
            return Ok(PreparedRewrapReview::Ready(Box::new((target, reviewed))));
        }
        Ok(PreparedRewrapReview::Review(Box::new(RewrapReview {
            target,
            digest,
            operation,
            requests,
            first_request_is_signer,
            non_member,
            accepted_non_member: None,
            reviewed,
            input_state,
            post_promotion_members: Some(members),
        })))
    }

    fn load_evaluators_and_recipients(
        &self,
    ) -> Result<(
        TrustPolicyEvaluator,
        TrustPolicyEvaluator,
        RecipientKeys,
        CurrentMemberSnapshot,
    )> {
        let snapshot = self.ensure_post_promotion_snapshot()?;
        let members = snapshot.members().clone();
        let recipients = snapshot.recipients().clone();
        let store = self.load_store()?;
        let output = TrustPolicyEvaluator::new(members.clone(), store);
        let input = output.with_members(self.pre_promotion_members.clone());
        Ok((input, output, recipients, members))
    }

    fn ensure_post_promotion_snapshot(&self) -> Result<super::snapshot::PostPromotionSnapshot> {
        let mut slot = self
            .post_promotion_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(snapshot) = slot.as_ref() {
            return Ok(snapshot.clone());
        }
        let snapshot = super::snapshot::PostPromotionSnapshot::load_at(&self.workspace)?;
        *slot = Some(snapshot.clone());
        Ok(snapshot)
    }

    fn load_input_evaluator(&self) -> Result<TrustPolicyEvaluator> {
        Ok(TrustPolicyEvaluator::new(
            self.pre_promotion_members.clone(),
            self.load_store()?,
        ))
    }

    fn load_store(&self) -> Result<Option<crate::service::trust::VerifiedLocalTrustStore>> {
        let Some(home) = self.home.as_ref() else {
            return Ok(None);
        };
        let Some(trust_dir) = self.opened_trust_directory()? else {
            return Ok(None);
        };
        LocalTrustStore::open_from_anchored_base(home, self.key_ctx.member_handle().clone())
            .load_verified_at(trust_dir, self.key_ctx.inner().local_keystore_access())
            .map(|loaded| loaded.map(|loaded| loaded.into_store()))
    }

    fn opened_trust_directory(&self) -> Result<Option<&OpenDir>> {
        if let Some(session) = self.trust_session {
            return Ok(session.trust_dir().map(Arc::as_ref));
        }
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

    fn ensured_trust_directory(&self) -> Result<&OpenDir> {
        if let Some(session) = self.trust_session {
            return session
                .ensured_trust_directory()
                .map(|directory| directory.as_ref());
        }
        if let Some(trust_dir) = self.trust_dir.get() {
            return Ok(trust_dir.as_ref());
        }
        let home = self.home.as_ref().ok_or_else(|| {
            Error::build_invalid_operation_error(
                "Local state is required to save trust approvals".to_string(),
            )
        })?;
        let opened = ensure_child_dir_restricted_at(home, TRUST_DIR_NAME)?;
        Ok(self.trust_dir.get_or_init(|| Arc::new(opened)).as_ref())
    }
}

impl RewrapReview {
    /// Return trust requests that must be persisted before resuming.
    pub fn requests(&self) -> &[TrustReviewRequest] {
        &self.requests
    }

    /// Return whether the first pending known-key request authorizes the signer.
    pub fn first_request_is_signer(&self) -> bool {
        self.first_request_is_signer
    }

    /// Return verified non-member review data for display.
    pub fn non_member_signer(&self) -> Option<&RewrapNonMemberReview> {
        self.non_member.as_ref()
    }

    /// Mint one acceptance for the exact signer, artifact, and operation.
    pub fn accept_non_member(&mut self) -> Result<RewrapAcceptance> {
        self.non_member
            .as_mut()
            .ok_or_else(|| {
                crate::Error::build_invalid_operation_error(
                    "This rewrap review has no non-member signer".to_string(),
                )
            })?
            .accept_non_member()
    }

    fn validate(&self, digest: [u8; 32], operation: RewrapOperationBinding) -> Result<()> {
        if self.digest == digest && self.operation == operation {
            return Ok(());
        }
        Err(crate::Error::build_verification_error(
            "E_TRUST_TARGET_CHANGED".to_string(),
            "Reviewed rewrap artifact or operation changed. Run the command again.".to_string(),
        ))
    }

    fn validate_state(
        &self,
        input: &TrustPolicyEvaluator,
        post_promotion_members: &CurrentMemberSnapshot,
    ) -> Result<()> {
        let input_matches = self.input_state.matches_state(input);
        let post_matches = self
            .post_promotion_members
            .as_ref()
            .is_none_or(|reviewed| reviewed == post_promotion_members);
        if input_matches && post_matches {
            return Ok(());
        }
        Err(target_changed_error())
    }

    fn expected_acceptance_review_id(&self) -> Option<Uuid> {
        self.non_member
            .as_ref()
            .map(|review| review.review_id)
            .or_else(|| {
                self.accepted_non_member
                    .as_ref()
                    .map(|acceptance| acceptance.review_id)
            })
    }
}

fn into_session_decision<'a>(
    decision: TrustDecision<AuthorizedRewrapInput<'a>>,
    digest: [u8; 32],
    operation: RewrapOperationBinding,
    accepted_non_member: Option<RewrapAcceptance>,
    publish_target: RewrapPublishTarget,
    input_state: TrustPolicyEvaluator,
    post_promotion_members: CurrentMemberSnapshot,
) -> Result<RewrapSessionDecision<AuthorizedRewrapInput<'a>>> {
    match decision {
        TrustDecision::Trusted(authorized) => Ok(RewrapSessionDecision::Authorized(
            authorized.with_publish_target(publish_target),
        )),
        TrustDecision::ReviewRequired(requests) => {
            let RewrapPublishTarget { target, reviewed } = publish_target;
            Ok(RewrapSessionDecision::ReviewRequired(Box::new(
                RewrapReview {
                    target,
                    digest,
                    operation,
                    requests,
                    first_request_is_signer: false,
                    non_member: None,
                    accepted_non_member,
                    reviewed,
                    input_state,
                    post_promotion_members: Some(post_promotion_members),
                },
            )))
        }
    }
}

impl RewrapNonMemberReview {
    pub(crate) fn from_verified(
        digest: [u8; 32],
        artifact_kind: RewrapArtifactKind,
        options: RewrapOptions,
        review: &NonMemberSignerReview,
    ) -> Self {
        Self {
            review_id: Uuid::new_v4(),
            digest,
            operation: RewrapOperationBinding {
                artifact_kind,
                options,
            },
            signer: (
                review.candidate().subject_handle().clone(),
                review.candidate().kid().clone(),
            ),
            candidate: review.candidate().clone(),
            recipient_handles: review.recipient_handles().to_vec(),
            acceptance_issued: false,
        }
    }

    /// Return the cryptographically verified signer candidate for display.
    pub fn candidate(&self) -> &KnownKeyReviewCandidate {
        &self.candidate
    }

    /// Return display-only recipient handles from the reviewed artifact.
    pub fn recipient_handles(&self) -> &[MemberHandle] {
        &self.recipient_handles
    }

    /// Mint one acceptance bound to this artifact, operation, and signer.
    pub fn accept_non_member(&mut self) -> Result<RewrapAcceptance> {
        if self.acceptance_issued {
            return Err(crate::Error::build_invalid_operation_error(
                "The rewrap non-member review was already accepted".to_string(),
            ));
        }
        self.acceptance_issued = true;
        Ok(RewrapAcceptance {
            review_id: self.review_id,
            digest: self.digest,
            operation: self.operation,
            signer: self.signer.clone(),
        })
    }
}

impl RewrapAcceptance {
    fn duplicate(&self) -> Self {
        Self {
            review_id: self.review_id,
            digest: self.digest,
            operation: self.operation,
            signer: self.signer.clone(),
        }
    }

    pub(crate) fn validate(
        self,
        digest: [u8; 32],
        artifact_kind: RewrapArtifactKind,
        options: RewrapOptions,
        candidate: &KnownKeyReviewCandidate,
    ) -> Result<(MemberHandle, Kid)> {
        let signer = (candidate.subject_handle().clone(), candidate.kid().clone());
        if self.review_id != Uuid::nil()
            && self.digest == digest
            && self.operation
                == (RewrapOperationBinding {
                    artifact_kind,
                    options,
                })
            && self.signer == signer
        {
            return Ok(signer);
        }
        Err(crate::Error::build_verification_error(
            "E_TRUST_TARGET_CHANGED".to_string(),
            "Reviewed rewrap target or signer changed. Run the command again.".to_string(),
        ))
    }
}

fn resolve_session_acceptance(
    supplied: Option<RewrapAcceptance>,
    retained: Option<RewrapAcceptance>,
    expected_review_id: Option<Uuid>,
) -> Result<Option<RewrapAcceptance>> {
    let acceptance = match (supplied, retained) {
        (Some(acceptance), None) | (None, Some(acceptance)) => Ok(Some(acceptance)),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(crate::Error::build_verification_error(
            "E_TRUST_TARGET_CHANGED".to_string(),
            "Rewrap non-member acceptance was reused. Run the command again.".to_string(),
        )),
    }?;
    let Some(acceptance) = acceptance else {
        return Ok(None);
    };
    if expected_review_id == Some(acceptance.review_id) {
        return Ok(Some(acceptance));
    }
    Err(target_changed_error())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/api_rewrap_test.rs"]
mod tests;
