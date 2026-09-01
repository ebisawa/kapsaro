// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Per-artifact rewrap review and execution.

use std::path::Path;

use crate::app::artifact::{detect_reviewed_artifact, load_reviewed_artifact, ArtifactRef};
use crate::app::context::execution::{enforce_selected_decryption_key_expiry, ExecutionContext};
use crate::app::context::review::ReviewedTextFile;
use crate::app::trust::recovery::classify_trust_store_reset;
use crate::app::trust::review::{
    review_artifact_output_recipient_set, review_rewrap_input_trust_requirements_with_confirmation,
    save_approved_known_key_documents, ArtifactOutputRecipientSetReviewInput,
    TrustExecutionContext,
};
use crate::app::trust::{
    build_read_artifact_trust_plan, load_read_trust_context, ArtifactRecipientTrustOutcome,
    RecipientTrustOutcome, SignerTrustOutcome, TrustApprovalCandidate, TrustContext,
};
use crate::feature::artifact::{artifact_wrap_set, verify_artifact_signature_for_operation};
use crate::format::content::EncContent;
use crate::model::verification::SignatureVerificationProof;
use crate::service::file::FileEncArtifact;
use crate::service::kv::KvEncArtifact;
use crate::service::trust::KnownKeyReview;
use crate::support::fs::lock;
use crate::support::path::{format_finding_path, format_path_relative_to_cwd};
use crate::support::warning::push_unique_warning;
use crate::Result;
use tracing::debug;

use super::rewrite::{build_rewritten_artifact, RewrapRewriteContext};
use super::types::{
    RewrapBatchOutcome, RewrapBatchPlan, RewrapBatchRequest, RewrapFileFailure, RewrapFileSuccess,
    RewrapInputTrustRequirement, VerifiedPostPromotionRecipients,
};

pub struct RewrapArtifactExecutionContext<'a> {
    pub request: &'a RewrapBatchRequest,
    pub plan: &'a RewrapBatchPlan,
    pub execution: &'a ExecutionContext,
    pub post_promotion_members: &'a VerifiedPostPromotionRecipients,
    pub post_promotion_trust: &'a TrustContext,
}

impl<'a> RewrapArtifactExecutionContext<'a> {
    pub fn new(
        request: &'a RewrapBatchRequest,
        plan: &'a RewrapBatchPlan,
        execution: &'a ExecutionContext,
        post_promotion_members: &'a VerifiedPostPromotionRecipients,
        post_promotion_trust: &'a TrustContext,
    ) -> Self {
        Self {
            request,
            plan,
            execution,
            post_promotion_members,
            post_promotion_trust,
        }
    }
}

struct RewrapArtifactConfirmations<
    'a,
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    ConfirmRecipientSet,
> {
    known: &'a mut ConfirmKnown,
    non_member: &'a mut ConfirmNonMember,
    recipients: &'a mut ConfirmRecipients,
    recipient_set: &'a mut ConfirmRecipientSet,
}

pub fn execute_rewrap_artifacts<
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    ConfirmRecipientSet,
>(
    ctx: &RewrapArtifactExecutionContext<'_>,
    confirm_known: &mut ConfirmKnown,
    confirm_non_member: &mut ConfirmNonMember,
    confirm_recipients: &mut ConfirmRecipients,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<RewrapBatchOutcome>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let mut confirmations = RewrapArtifactConfirmations {
        known: confirm_known,
        non_member: confirm_non_member,
        recipients: confirm_recipients,
        recipient_set: confirm_recipient_set,
    };
    execute_planned_rewrap_artifacts(ctx, &mut confirmations)
}

fn execute_planned_rewrap_artifacts<
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    ConfirmRecipientSet,
>(
    ctx: &RewrapArtifactExecutionContext<'_>,
    confirmations: &mut RewrapArtifactConfirmations<
        '_,
        ConfirmKnown,
        ConfirmNonMember,
        ConfirmRecipients,
        ConfirmRecipientSet,
    >,
) -> Result<RewrapBatchOutcome>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let mut processed_files = Vec::new();
    let mut failed_files = Vec::new();
    let mut warnings = Vec::new();

    for artifact in &ctx.plan.artifacts {
        match execute_rewrap_file(artifact, ctx, &mut warnings, confirmations) {
            Ok(()) => processed_files.push(RewrapFileSuccess {
                output_path: artifact.path().to_path_buf(),
            }),
            Err(error) if classify_trust_store_reset(&error).is_some() => return Err(error),
            Err(error) => failed_files.push(RewrapFileFailure {
                output_path: artifact.path().to_path_buf(),
                error_message: error.format_user_message().to_string(),
            }),
        }
    }

    Ok(build_rewrap_batch_outcome(
        processed_files,
        failed_files,
        warnings,
    ))
}

fn build_rewrap_batch_outcome(
    processed_files: Vec<RewrapFileSuccess>,
    failed_files: Vec<RewrapFileFailure>,
    warnings: Vec<String>,
) -> RewrapBatchOutcome {
    RewrapBatchOutcome {
        processed_files,
        failed_files,
        promoted_member_handles: Vec::new(),
        warnings,
    }
}

fn execute_rewrap_file<ConfirmKnown, ConfirmNonMember, ConfirmRecipients, ConfirmRecipientSet>(
    artifact: &ArtifactRef,
    ctx: &RewrapArtifactExecutionContext<'_>,
    warnings: &mut Vec<String>,
    confirmations: &mut RewrapArtifactConfirmations<
        '_,
        ConfirmKnown,
        ConfirmNonMember,
        ConfirmRecipients,
        ConfirmRecipientSet,
    >,
) -> Result<()>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    debug!(
        "[REWRAP] artifact: process path={}",
        format_path_relative_to_cwd(artifact.path())
    );
    let (captured, content) = load_rewrap_artifact_content(artifact)?;
    execute_loaded_rewrap_file(artifact, &captured, &content, ctx, warnings, confirmations)
}

fn load_rewrap_artifact_content(artifact: &ArtifactRef) -> Result<(ReviewedTextFile, EncContent)> {
    let captured = load_reviewed_artifact(artifact)?;
    let content = detect_reviewed_artifact(&captured)?;
    Ok((captured, content))
}

fn execute_loaded_rewrap_file<
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    ConfirmRecipientSet,
>(
    artifact: &ArtifactRef,
    captured: &ReviewedTextFile,
    content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
    warnings: &mut Vec<String>,
    confirmations: &mut RewrapArtifactConfirmations<
        '_,
        ConfirmKnown,
        ConfirmNonMember,
        ConfirmRecipients,
        ConfirmRecipientSet,
    >,
) -> Result<()>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    collect_rewrap_file_warning(content, ctx, warnings)?;
    review_captured_artifact_signer(
        captured,
        content,
        ctx,
        warnings,
        confirmations.known,
        confirmations.non_member,
        confirmations.recipients,
    )?;
    execute_rewrap_artifact_replacement(
        artifact,
        captured,
        content,
        ctx,
        confirmations.recipient_set,
    )
}

fn collect_rewrap_file_warning(
    content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    if let Some(warning) = build_rewrap_decryption_key_warning(content, ctx)? {
        push_unique_warning(warnings, warning);
    }
    Ok(())
}

fn execute_rewrap_artifact_replacement<ConfirmRecipientSet>(
    artifact: &ArtifactRef,
    captured: &ReviewedTextFile,
    content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<()>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let rewritten =
        rewrite_and_review_output_artifact(artifact.path(), content, ctx, confirm_recipient_set)?;
    save_rewritten_artifact(artifact, captured, &rewritten)
}

/// Replace the artifact through the descriptor it was listed under.
///
/// That descriptor is locked and the entry addressed relative to it, so the
/// write lands in the very directory the artifact was read from even if the
/// path naming it is repointed in between, and no other kapsaro process is
/// writing the same tree while it runs.
///
/// The stored entry is confirmed to be the reviewed one first, by identity as
/// well as by content. Approval prompts run between the read and this write, so
/// an edit made while the operator was deciding would otherwise be overwritten
/// without anyone seeing it go, and a name repointed at another regular file
/// holding the same bytes would take the rewrapped secrets with it.
fn save_rewritten_artifact(
    artifact: &ArtifactRef,
    captured: &ReviewedTextFile,
    rewritten: &str,
) -> Result<()> {
    lock::with_exclusive_locked_directory(artifact.directory().as_ref(), |locked_dir| {
        captured.ensure_identity_and_content_current_at(locked_dir)?;
        captured.save_replacement_at(locked_dir, rewritten)
    })
}

fn rewrite_and_review_output_artifact<ConfirmRecipientSet>(
    file_path: &Path,
    content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<String>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let rewrite_ctx = RewrapRewriteContext {
        request: ctx.request,
        execution: ctx.execution,
        post_promotion_members: ctx.post_promotion_members,
    };
    let rewritten = build_rewritten_artifact(content, &rewrite_ctx)?;
    // The name reaches the operator inside a parse failure on standard error,
    // and it comes from a scan of `secrets/`, which holds whatever a teammate
    // committed.
    let rewritten_content =
        EncContent::detect_with_source(rewritten.clone(), format_finding_path(file_path))?;
    review_rewrap_output_recipient_set(&rewritten_content, ctx, confirm_recipient_set)?;
    Ok(rewritten)
}

fn review_rewrap_output_recipient_set<ConfirmRecipientSet>(
    rewritten_content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<()>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    review_artifact_output_recipient_set(
        ArtifactOutputRecipientSetReviewInput {
            options: &ctx.request.options,
            execution: ctx.execution,
            trust_ctx: ctx.post_promotion_trust,
            content: rewritten_content,
            context_label: "rewrap output member set",
        },
        confirm_recipient_set,
    )
}

fn build_rewrap_decryption_key_warning(
    content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
) -> Result<Option<String>> {
    let wrap_set = artifact_wrap_set(content)?;
    enforce_selected_decryption_key_expiry(
        ctx.execution,
        &wrap_set,
        ctx.request.options.allow_expired_key,
    )
}

fn review_captured_artifact_signer<ConfirmKnown, ConfirmNonMember, ConfirmRecipients>(
    captured: &ReviewedTextFile,
    content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
    warnings: &mut Vec<String>,
    confirm_known: &mut ConfirmKnown,
    confirm_non_member: &mut ConfirmNonMember,
    confirm_recipients: &mut ConfirmRecipients,
) -> Result<()>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    let trust_ctx = load_rewrap_signer_trust_context(ctx.request, ctx.plan, ctx.execution)?;
    let Some(requirement) = build_rewrap_input_trust_requirement(
        captured,
        content,
        &trust_ctx,
        ctx.execution,
        ctx.post_promotion_members,
        ctx.request.options.allow_expired_key,
        warnings,
    )?
    else {
        return Ok(());
    };
    let approvals = review_rewrap_input_trust_requirements_with_confirmation(
        std::slice::from_ref(&requirement),
        "rewrap input signer",
        "signer trust",
        confirm_known,
        confirm_non_member,
        confirm_recipients,
    )?;
    save_approved_known_key_documents(
        TrustExecutionContext {
            options: &ctx.request.options,
            execution: ctx.execution,
        },
        &approvals,
    )?;
    Ok(())
}

fn load_rewrap_signer_trust_context(
    request: &RewrapBatchRequest,
    plan: &RewrapBatchPlan,
    execution: &ExecutionContext,
) -> Result<TrustContext> {
    let mut trust_ctx = load_read_trust_context(&request.options, execution, "rewrap")?.trust_ctx;
    trust_ctx.active_members_by_kid = plan.pre_promotion_trust.active_members_by_kid.clone();
    trust_ctx.is_interactive = plan.pre_promotion_trust.is_interactive;
    trust_ctx.allow_non_member = plan.pre_promotion_trust.allow_non_member;
    Ok(trust_ctx)
}

fn build_rewrap_input_trust_requirement(
    captured: &ReviewedTextFile,
    content: &EncContent,
    trust_ctx: &TrustContext,
    execution: &ExecutionContext,
    post_promotion_members: &VerifiedPostPromotionRecipients,
    allow_expired_key: bool,
    warnings: &mut Vec<String>,
) -> Result<Option<RewrapInputTrustRequirement>> {
    debug!("[REWRAP] input signer: verify captured artifact proof");
    let proof = extract_signature_proof(content, allow_expired_key)?;
    for warning in &proof.warnings {
        push_unique_warning(warnings, warning.clone());
    }
    let evaluator = crate::app::trust::snapshot::load_trust_policy_evaluator(
        execution,
        trust_ctx.active_members_by_kid.clone(),
    )?;
    let allow_non_member = trust_ctx.is_interactive && trust_ctx.allow_non_member;
    let review = match content {
        EncContent::FileEnc(content) => evaluator.preflight_file_read(
            &FileEncArtifact::parse(content.as_str())?.verify(
                crate::service::operation::OperationOptions::new()
                    .with_allow_expired_key(allow_expired_key),
            )?,
            &execution.key_ctx,
            KnownKeyReview::Required,
            allow_non_member,
        )?,
        EncContent::KvEnc(content) => evaluator.preflight_kv_read(
            &KvEncArtifact::parse(content.as_str())?.verify(
                crate::service::operation::OperationOptions::new()
                    .with_allow_expired_key(allow_expired_key),
            )?,
            &execution.key_ctx,
            KnownKeyReview::Required,
            allow_non_member,
        )?,
    };
    let mut plan = build_read_artifact_trust_plan(
        review,
        &proof,
        KnownKeyReview::Required,
        trust_ctx.is_interactive,
        Vec::new(),
    )?;
    for warning in plan.warnings.drain(..) {
        push_unique_warning(warnings, warning);
    }
    if let SignerTrustOutcome::NeedsNonMemberAcceptance {
        current_recipients, ..
    } = &mut plan.signer_outcome
    {
        *current_recipients = post_promotion_members.recipient_handles().to_vec();
    }
    if input_trust_accepted(&plan.signer_outcome, &plan.recipient_outcome) {
        return Ok(None);
    }
    Ok(Some(RewrapInputTrustRequirement {
        file_path: captured.path().to_path_buf(),
        signer_outcome: plan.signer_outcome,
        recipient_outcome: plan.recipient_outcome,
    }))
}

fn input_trust_accepted(
    signer_outcome: &SignerTrustOutcome,
    recipient_outcome: &RecipientTrustOutcome,
) -> bool {
    matches!(signer_outcome, SignerTrustOutcome::Accepted)
        && matches!(recipient_outcome, RecipientTrustOutcome::Accepted)
}

fn extract_signature_proof(
    content: &EncContent,
    allow_expired_key: bool,
) -> Result<SignatureVerificationProof> {
    verify_artifact_signature_for_operation(content, allow_expired_key)
}
