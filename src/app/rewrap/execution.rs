// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::execution::ExecutionContext;
use crate::app::trust::approval::{save_known_key_approvals, ApprovedKnownKey};
use crate::app::trust::TrustApprovalCandidate;
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::Result;

use super::artifact::{execute_rewrap_artifacts, RewrapArtifactExecutionContext};
use super::session::RewrapReviewSession;
use super::snapshot::{load_verified_post_promotion_members, promote_accepted_incoming_members};
use super::types::{
    RewrapBatchOutcome, RewrapBatchPlan, RewrapBatchRequest, VerifiedPostPromotionRecipients,
};

pub(crate) fn execute_confirmed_rewrap_batch<ConfirmKnown, ConfirmNonMember>(
    review_session: RewrapReviewSession,
    execution: ExecutionContext,
    mut confirm_known: ConfirmKnown,
    mut confirm_non_member: ConfirmNonMember,
) -> Result<RewrapBatchOutcome>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &Path) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String], &Path) -> Result<bool>,
{
    let promoted_member_handles = promote_accepted_incoming_members(
        &review_session.plan.workspace_root,
        &review_session.request.accepted_promotions,
    )?;
    let actual_post_promotion_members = load_verified_post_promotion_members(
        &review_session.plan.workspace_root,
        &review_session.expected_post_promotion_members,
    )?;
    enforce_key_not_expired_for_signing(&execution.key_ctx.expires_at)?;
    let mut approval_warnings = save_known_key_approval_warnings(
        &review_session.request.options,
        &execution,
        &review_session.approvals,
    )?;
    let mut outcome = execute_reviewed_rewrap_artifacts(
        &review_session.request,
        &review_session.plan,
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

/// Execute artifact rewrites after promotion and recipient review have completed.
pub(crate) fn execute_reviewed_rewrap_artifacts<ConfirmKnown, ConfirmNonMember>(
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
    let ctx =
        RewrapArtifactExecutionContext::new(request, plan, &execution, post_promotion_members);
    execute_rewrap_artifacts(&ctx, confirm_known, confirm_non_member)
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

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_rewrap_execution_test.rs"]
mod tests;
