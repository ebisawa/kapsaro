// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Per-artifact rewrap review and execution.

use std::path::Path;

use crate::app::context::execution::ExecutionContext;
use crate::app::context::review::ReviewedTextFile;
use crate::app::trust::approval::{save_known_key_approvals, ApprovedKnownKey};
use crate::app::trust::review::review_rewrap_signer_requirements_with_confirmation;
use crate::app::trust::{
    derive_self_sig_x, evaluate_signer_trust_with_proof, load_read_trust_context,
    CommandCapability, TrustApprovalCandidate, TrustContext,
};
use crate::feature::verify::file::verify_file_content;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::EncContent;
use crate::model::verification::SignatureVerificationProof;
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;

use super::rewrite::{rewrite_captured_artifact, RewrapRewriteContext};
use super::types::{
    RewrapBatchOutcome, RewrapBatchPlan, RewrapBatchRequest, RewrapFileFailure, RewrapFileSuccess,
    RewrapSignerRequirement, VerifiedPostPromotionRecipients,
};

pub(crate) struct RewrapArtifactExecutionContext<'a> {
    pub(crate) request: &'a RewrapBatchRequest,
    pub(crate) plan: &'a RewrapBatchPlan,
    pub(crate) execution: &'a ExecutionContext,
    pub(crate) post_promotion_members: &'a VerifiedPostPromotionRecipients,
    pub(crate) current_recipients: Vec<String>,
}

impl<'a> RewrapArtifactExecutionContext<'a> {
    pub(crate) fn new(
        request: &'a RewrapBatchRequest,
        plan: &'a RewrapBatchPlan,
        execution: &'a ExecutionContext,
        post_promotion_members: &'a VerifiedPostPromotionRecipients,
    ) -> Self {
        Self {
            request,
            plan,
            execution,
            post_promotion_members,
            current_recipients: collect_current_recipient_handles(post_promotion_members),
        }
    }
}

pub(crate) fn execute_rewrap_artifacts<ConfirmKnown, ConfirmNonMember>(
    ctx: &RewrapArtifactExecutionContext<'_>,
    confirm_known: &mut ConfirmKnown,
    confirm_non_member: &mut ConfirmNonMember,
) -> Result<RewrapBatchOutcome>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &Path) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String], &Path) -> Result<bool>,
{
    let mut processed_files = Vec::new();
    let mut failed_files = Vec::new();
    let mut warnings = Vec::new();

    for file_path in &ctx.plan.artifact_paths {
        match execute_rewrap_file(
            file_path,
            ctx,
            &mut warnings,
            confirm_known,
            confirm_non_member,
        ) {
            Ok(()) => processed_files.push(RewrapFileSuccess {
                output_path: file_path.clone(),
            }),
            Err(error) => failed_files.push(RewrapFileFailure {
                output_path: file_path.clone(),
                error_message: error.format_user_message().to_string(),
            }),
        }
    }

    Ok(RewrapBatchOutcome {
        processed_files,
        failed_files,
        promoted_member_handles: Vec::new(),
        warnings,
    })
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

fn execute_rewrap_file<ConfirmKnown, ConfirmNonMember>(
    file_path: &Path,
    ctx: &RewrapArtifactExecutionContext<'_>,
    warnings: &mut Vec<String>,
    confirm_known: &mut ConfirmKnown,
    confirm_non_member: &mut ConfirmNonMember,
) -> Result<()>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &Path) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String], &Path) -> Result<bool>,
{
    let captured = load_captured_artifact(file_path)?;
    let content = EncContent::detect_with_source(
        captured.require_content()?.to_string(),
        format_path_relative_to_cwd(file_path),
    )?;
    review_captured_artifact_signer(
        &captured,
        &content,
        ctx,
        warnings,
        confirm_known,
        confirm_non_member,
    )?;
    let rewrite_ctx = RewrapRewriteContext {
        request: ctx.request,
        plan: ctx.plan,
        execution: ctx.execution,
        post_promotion_members: ctx.post_promotion_members,
    };
    rewrite_captured_artifact(&captured, &content, &rewrite_ctx)
}

fn load_captured_artifact(file_path: &Path) -> Result<ReviewedTextFile> {
    ReviewedTextFile::load_existing(
        file_path,
        "encrypted artifact",
        resolve_encrypted_artifact_read_limit(file_path),
    )
}

fn review_captured_artifact_signer<ConfirmKnown, ConfirmNonMember>(
    captured: &ReviewedTextFile,
    content: &EncContent,
    ctx: &RewrapArtifactExecutionContext<'_>,
    warnings: &mut Vec<String>,
    confirm_known: &mut ConfirmKnown,
    confirm_non_member: &mut ConfirmNonMember,
) -> Result<()>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &Path) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String], &Path) -> Result<bool>,
{
    let trust_ctx = load_rewrap_signer_trust_context(ctx.request, ctx.plan, ctx.execution)?;
    let Some(requirement) =
        build_rewrap_signer_requirement(captured, content, &trust_ctx, &ctx.current_recipients)?
    else {
        return Ok(());
    };
    let approvals = review_rewrap_signer_requirements_with_confirmation(
        std::slice::from_ref(&requirement),
        "rewrap input signer",
        "signer trust",
        confirm_known,
        confirm_non_member,
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
        Some(derive_self_sig_x(&execution.key_ctx.signing_key)),
        request.options.verbose,
    )?
    .trust_ctx;
    trust_ctx.active_members_by_kid = plan.pre_promotion_trust.active_members_by_kid.clone();
    trust_ctx.is_interactive = plan.pre_promotion_trust.is_interactive;
    Ok(trust_ctx)
}

fn build_rewrap_signer_requirement(
    captured: &ReviewedTextFile,
    content: &EncContent,
    trust_ctx: &TrustContext,
    current_recipients: &[String],
) -> Result<Option<RewrapSignerRequirement>> {
    let proof = extract_signature_proof(content)?;
    let outcome = evaluate_signer_trust_with_proof(
        trust_ctx,
        &proof,
        CommandCapability::Rewrap,
        current_recipients,
    )?;
    if matches!(outcome, crate::app::trust::SignerTrustOutcome::Accepted) {
        return Ok(None);
    }
    Ok(Some(RewrapSignerRequirement {
        file_path: captured.path().to_path_buf(),
        outcome,
    }))
}

fn extract_signature_proof(content: &EncContent) -> Result<SignatureVerificationProof> {
    match content {
        EncContent::FileEnc(file_content) => {
            Ok(verify_file_content(file_content, false)?.proof.clone())
        }
        EncContent::KvEnc(kv_content) => Ok(verify_kv_content(kv_content, false)?.proof),
    }
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
