// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::context::review::{ensure_public_key_snapshot_matches, ReviewedTextFile};
use crate::app::trust::approval::{save_known_key_approvals, ApprovedKnownKey};
use crate::app::trust::review::review_rewrap_signer_requirements_with_confirmation;
use crate::app::trust::{
    derive_self_sig_x, evaluate_signer_trust_with_proof, load_read_trust_context,
    CommandCapability, TrustApprovalCandidate, TrustContext,
};
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::feature::rewrap::{rewrap_content as rewrap_feature_content, RewrapRequest};
use crate::feature::verify::file::verify_file_content;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::format::content::EncContent;
use crate::io::workspace::members::{
    load_active_member_files, promote_snapshotted_incoming_members, IncomingMemberPromotionSnapshot,
};
use crate::model::verification::SignatureVerificationProof;
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;
use std::path::Path;

use super::types::{
    RewrapBatchOutcome, RewrapBatchPlan, RewrapBatchRequest, RewrapFileFailure, RewrapFileSuccess,
    RewrapSignerRequirement, VerifiedPostPromotionRecipients,
};

struct RewrapBatchExecutionContext<'a> {
    plan: &'a RewrapBatchPlan,
    execution: &'a ExecutionContext,
    request: &'a RewrapBatchRequest,
    post_promotion_members: &'a VerifiedPostPromotionRecipients,
    current_recipients: &'a [String],
}

pub(crate) fn promote_accepted_incoming_members(
    workspace_root: &Path,
    accepted_promotions: &[crate::app::rewrap::types::IncomingPromotionCandidate],
) -> Result<Vec<String>> {
    if accepted_promotions.is_empty() {
        return Ok(Vec::new());
    }
    let snapshots = accepted_promotions
        .iter()
        .map(|candidate| IncomingMemberPromotionSnapshot {
            member_handle: candidate.review.member_handle.clone(),
            kid: candidate.review.kid.clone(),
            source_path: candidate.source_path.clone(),
            source_content: candidate.source_content.clone(),
        })
        .collect::<Vec<_>>();
    promote_snapshotted_incoming_members(workspace_root, &snapshots)
}

pub(crate) fn execute_confirmed_rewrap_batch<ConfirmKnown, ConfirmNonMember>(
    request: &RewrapBatchRequest,
    plan: &RewrapBatchPlan,
    expected_post_promotion_members: &[crate::model::public_key::PublicKey],
    execution: ExecutionContext,
    approvals: &[ApprovedKnownKey],
    mut confirm_known: ConfirmKnown,
    mut confirm_non_member: ConfirmNonMember,
) -> Result<RewrapBatchOutcome>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &Path) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String], &Path) -> Result<bool>,
{
    let promoted_member_handles =
        promote_accepted_incoming_members(&plan.workspace_root, &request.accepted_promotions)?;
    let actual_post_promotion_members = load_verified_post_promotion_members(
        &plan.workspace_root,
        expected_post_promotion_members,
    )?;
    enforce_key_not_expired_for_signing(&execution.key_ctx.expires_at)?;
    let mut approval_warnings =
        save_known_key_approval_warnings(&request.options, &execution, approvals)?;
    let mut outcome = execute_rewrap_batch(
        request,
        plan,
        execution,
        &actual_post_promotion_members,
        &mut confirm_known,
        &mut confirm_non_member,
    )?;
    outcome.promoted_member_handles = promoted_member_handles;
    approval_warnings.extend(outcome.warnings);
    outcome.warnings = approval_warnings;
    Ok(outcome)
}

/// Execute a batch rewrap over already planned files.
pub(crate) fn execute_rewrap_batch<ConfirmKnown, ConfirmNonMember>(
    request: &RewrapBatchRequest,
    plan: &RewrapBatchPlan,
    execution: ExecutionContext,
    post_promotion_members: &VerifiedPostPromotionRecipients,
    confirm_known: &mut ConfirmKnown,
    confirm_non_member: &mut ConfirmNonMember,
) -> Result<RewrapBatchOutcome>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &Path) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String], &Path) -> Result<bool>,
{
    enforce_key_not_expired_for_signing(&execution.key_ctx.expires_at)?;
    let mut processed_files = Vec::new();
    let mut failed_files = Vec::new();
    let mut warnings = Vec::new();
    let current_recipients = collect_current_recipient_handles(post_promotion_members);
    let ctx = RewrapBatchExecutionContext {
        plan,
        execution: &execution,
        request,
        post_promotion_members,
        current_recipients: &current_recipients,
    };

    for file_path in &plan.artifact_paths {
        match execute_rewrap_file(
            file_path,
            &ctx,
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

fn load_verified_post_promotion_members(
    workspace_root: &Path,
    expected: &[crate::model::public_key::PublicKey],
) -> Result<VerifiedPostPromotionRecipients> {
    let actual = load_active_member_files(workspace_root)?;
    ensure_post_promotion_members_match(expected, &actual)?;
    let verified_members = verify_recipient_public_keys(&actual, false)?;
    Ok(VerifiedPostPromotionRecipients::new(verified_members))
}

fn ensure_post_promotion_members_match(
    expected: &[crate::model::public_key::PublicKey],
    actual: &[crate::model::public_key::PublicKey],
) -> Result<()> {
    ensure_public_key_snapshot_matches(
        expected,
        actual,
        "Rewrap post-promotion active members changed and must be reviewed again.",
    )
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
    ctx: &RewrapBatchExecutionContext<'_>,
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
    rewrite_captured_artifact(&captured, &content, ctx)
}

fn load_captured_artifact(file_path: &Path) -> Result<ReviewedTextFile> {
    ReviewedTextFile::load_existing(
        file_path,
        "encrypted artifact",
        resolve_encrypted_artifact_read_limit(file_path),
    )
}

fn rewrite_captured_artifact(
    captured: &ReviewedTextFile,
    content: &EncContent,
    ctx: &RewrapBatchExecutionContext<'_>,
) -> Result<()> {
    let rewrap_request = build_rewrap_request(ctx);
    let rewritten = rewrap_feature_content(content, &rewrap_request)?;
    save_rewritten_artifact(captured, &rewritten)
}

fn build_rewrap_request<'a>(ctx: &'a RewrapBatchExecutionContext<'a>) -> RewrapRequest<'a> {
    RewrapRequest {
        member_handle: ctx.execution.member_handle.as_str(),
        key_ctx: &ctx.execution.key_ctx,
        workspace_root: Some(ctx.plan.workspace_root.as_path()),
        target_members: Some(ctx.post_promotion_members.verified_members()),
        rotate_key: ctx.request.rotate_key,
        clear_disclosure_history: ctx.request.clear_disclosure_history,
        debug: ctx.request.options.verbose,
    }
}

fn save_rewritten_artifact(captured: &ReviewedTextFile, rewritten: &str) -> Result<()> {
    captured.save_replacement(rewritten)
}

fn review_captured_artifact_signer<ConfirmKnown, ConfirmNonMember>(
    captured: &ReviewedTextFile,
    content: &EncContent,
    ctx: &RewrapBatchExecutionContext<'_>,
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
        build_rewrap_signer_requirement(captured, content, &trust_ctx, ctx.current_recipients)?
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

#[cfg(test)]
#[path = "../../../tests/unit/app_rewrap_execution_test.rs"]
mod tests;
