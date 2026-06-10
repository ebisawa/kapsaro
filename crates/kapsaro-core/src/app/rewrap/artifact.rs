// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Per-artifact rewrap review and execution.

use std::path::Path;

use crate::app::artifact::{detect_reviewed_artifact, load_reviewed_artifact};
use crate::app::context::execution::{enforce_selected_decryption_key_expiry, ExecutionContext};
use crate::app::context::review::ReviewedTextFile;
use crate::app::trust::approval::{save_known_key_approvals, ApprovedKnownKey};
use crate::app::trust::enforcement::evaluate_read_artifact_recipient_keys;
use crate::app::trust::recovery::requires_trust_store_reset;
use crate::app::trust::review::{
    review_artifact_output_recipient_set, review_rewrap_input_trust_requirements_with_confirmation,
    ArtifactOutputRecipientSetReviewInput,
};
use crate::app::trust::{
    evaluate_signer_trust_with_proof, load_read_trust_context, ArtifactRecipientTrustOutcome,
    CommandCapability, RecipientTrustOutcome, SignerTrustOutcome, TrustApprovalCandidate,
    TrustContext,
};
use crate::feature::artifact::{
    artifact_recipient_evidence, artifact_wrap_set, verify_artifact_signature_for_operation,
};
use crate::format::content::EncContent;
use crate::model::verification::SignatureVerificationProof;
use crate::support::path::format_path_relative_to_cwd;
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
    pub current_recipients: Vec<String>,
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
            current_recipients: collect_current_recipient_handles(post_promotion_members),
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
    execute_rewrap_artifact_paths(ctx, &mut confirmations)
}

fn execute_rewrap_artifact_paths<
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

    for file_path in &ctx.plan.artifact_paths {
        match execute_rewrap_file(file_path, ctx, &mut warnings, confirmations) {
            Ok(()) => processed_files.push(RewrapFileSuccess {
                output_path: file_path.clone(),
            }),
            Err(error) if requires_trust_store_reset(&error) => return Err(error),
            Err(error) => failed_files.push(RewrapFileFailure {
                output_path: file_path.clone(),
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

fn collect_current_recipient_handles(
    post_promotion_members: &VerifiedPostPromotionRecipients,
) -> Vec<String> {
    let mut recipients = post_promotion_members
        .verified_members()
        .iter()
        .map(|member| member.document().protected.subject_handle.clone())
        .collect::<Vec<_>>();
    recipients.sort();
    recipients
}

fn execute_rewrap_file<ConfirmKnown, ConfirmNonMember, ConfirmRecipients, ConfirmRecipientSet>(
    file_path: &Path,
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
    if ctx.request.options.debug {
        debug!(
            "[REWRAP] artifact: process path={}",
            format_path_relative_to_cwd(file_path)
        );
    }
    let (captured, content) = load_rewrap_artifact_content(file_path)?;
    execute_loaded_rewrap_file(file_path, &captured, &content, ctx, warnings, confirmations)
}

fn load_rewrap_artifact_content(file_path: &Path) -> Result<(ReviewedTextFile, EncContent)> {
    let captured = load_reviewed_artifact(file_path)?;
    let content = detect_reviewed_artifact(&captured)?;
    Ok((captured, content))
}

fn execute_loaded_rewrap_file<
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    ConfirmRecipientSet,
>(
    file_path: &Path,
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
        file_path,
        captured,
        content,
        ctx,
        warnings,
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
    file_path: &Path,
    captured: &ReviewedTextFile,
    content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
    warnings: &mut Vec<String>,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<()>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let rewritten = rewrite_and_review_output_artifact(
        file_path,
        content,
        ctx,
        warnings,
        confirm_recipient_set,
    )?;
    captured.save_replacement(&rewritten)
}

fn rewrite_and_review_output_artifact<ConfirmRecipientSet>(
    file_path: &Path,
    content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
    warnings: &mut Vec<String>,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<String>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let rewrite_ctx = RewrapRewriteContext {
        request: ctx.request,
        plan: ctx.plan,
        execution: ctx.execution,
        post_promotion_members: ctx.post_promotion_members,
    };
    let rewritten = build_rewritten_artifact(content, &rewrite_ctx)?;
    let rewritten_content =
        EncContent::detect_with_source(rewritten.clone(), format_path_relative_to_cwd(file_path))?;
    review_rewrap_output_recipient_set(&rewritten_content, ctx, warnings, confirm_recipient_set)?;
    Ok(rewritten)
}

fn review_rewrap_output_recipient_set<ConfirmRecipientSet>(
    rewritten_content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
    warnings: &mut Vec<String>,
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
            capability: CommandCapability::Rewrap,
            context_label: "rewrap output member set",
        },
        warnings,
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
        ctx.request.options.debug,
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
        ctx.request.options.allow_expired_key,
        ctx.request.options.debug,
        &ctx.current_recipients,
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
    warnings.extend(save_known_key_approval_warnings(
        &ctx.request.options,
        ctx.execution,
        &approvals,
    )?);
    Ok(())
}

fn load_rewrap_signer_trust_context(
    request: &RewrapBatchRequest,
    plan: &RewrapBatchPlan,
    execution: &ExecutionContext,
) -> Result<TrustContext> {
    let mut trust_ctx = load_read_trust_context(
        &request.options,
        &plan.workspace_root,
        &execution.member_handle,
        Some(execution.key_ctx.self_signature_public_key_x()),
        Some(execution.key_ctx.local_key_identity()),
        request.options.debug,
    )?
    .trust_ctx;
    trust_ctx.active_members_by_kid = plan.pre_promotion_trust.active_members_by_kid.clone();
    trust_ctx.is_interactive = plan.pre_promotion_trust.is_interactive;
    trust_ctx.allow_non_member = plan.pre_promotion_trust.allow_non_member;
    Ok(trust_ctx)
}

fn build_rewrap_input_trust_requirement(
    captured: &ReviewedTextFile,
    content: &EncContent,
    trust_ctx: &TrustContext,
    allow_expired_key: bool,
    debug_enabled: bool,
    current_recipients: &[String],
    warnings: &mut Vec<String>,
) -> Result<Option<RewrapInputTrustRequirement>> {
    if debug_enabled {
        debug!("[REWRAP] input signer: verify captured artifact proof");
    }
    let proof = extract_signature_proof(content, allow_expired_key, debug_enabled)?;
    for warning in &proof.warnings {
        push_unique_warning(warnings, warning.clone());
    }
    let recipient_evidence = artifact_recipient_evidence(content)?;
    let recipient_trust =
        evaluate_read_artifact_recipient_keys(trust_ctx, &recipient_evidence.recipient_set)?;
    warnings.extend(recipient_trust.warnings);
    let signer_outcome = evaluate_signer_trust_with_proof(
        trust_ctx,
        &proof,
        CommandCapability::Rewrap,
        current_recipients,
    )?;
    if input_trust_accepted(&signer_outcome, &recipient_trust.outcome) {
        return Ok(None);
    }
    Ok(Some(RewrapInputTrustRequirement {
        file_path: captured.path().to_path_buf(),
        signer_outcome,
        recipient_outcome: recipient_trust.outcome,
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
    debug_enabled: bool,
) -> Result<SignatureVerificationProof> {
    verify_artifact_signature_for_operation(content, debug_enabled, allow_expired_key)
}

fn save_known_key_approval_warnings(
    options: &crate::app::context::options::CommonCommandOptions,
    execution: &ExecutionContext,
    approvals: &[ApprovedKnownKey],
) -> Result<Vec<String>> {
    if approvals.is_empty() {
        return Ok(Vec::new());
    }
    Ok(save_known_key_approvals(options, execution, approvals)?.warnings)
}
