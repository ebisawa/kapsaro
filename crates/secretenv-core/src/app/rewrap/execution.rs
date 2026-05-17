// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::trust::review::{save_approved_known_key_warnings, TrustExecutionContext};
use crate::app::trust::{ArtifactRecipientTrustOutcome, TrustApprovalCandidate};
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::Result;

use super::artifact::{execute_rewrap_artifacts, RewrapArtifactExecutionContext};
use super::session::RewrapReviewSession;
use super::snapshot::{load_verified_post_promotion_members, promote_accepted_incoming_members};
use super::types::{
    RewrapBatchOutcome, RewrapBatchPlan, RewrapBatchRequest, VerifiedPostPromotionRecipients,
};
use crate::app::trust::TrustContext;

pub fn execute_confirmed_rewrap_batch<
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    ConfirmRecipientSet,
>(
    review_session: RewrapReviewSession,
    execution: ExecutionContext,
    mut confirm_known: ConfirmKnown,
    mut confirm_non_member: ConfirmNonMember,
    mut confirm_recipients: ConfirmRecipients,
    mut confirm_recipient_set: ConfirmRecipientSet,
) -> Result<RewrapBatchOutcome>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
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
    let mut approval_warnings = save_approved_known_key_warnings(
        TrustExecutionContext {
            options: &review_session.request.options,
            execution: &execution,
            warnings: &[],
        },
        &review_session.approvals,
    )?;
    let mut outcome = execute_reviewed_rewrap_artifacts(
        &review_session.request,
        &review_session.plan,
        execution,
        &actual_post_promotion_members,
        &review_session.post_promotion_trust,
        &mut confirm_known,
        &mut confirm_non_member,
        &mut confirm_recipients,
        &mut confirm_recipient_set,
    )?;
    outcome.promoted_member_handles = promoted_member_handles;
    approval_warnings.extend(outcome.warnings);
    outcome.warnings = approval_warnings;
    Ok(outcome)
}

/// Execute artifact rewrites after promotion and recipient review have completed.
#[allow(clippy::too_many_arguments)]
pub fn execute_reviewed_rewrap_artifacts<
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    ConfirmRecipientSet,
>(
    request: &RewrapBatchRequest,
    plan: &RewrapBatchPlan,
    execution: ExecutionContext,
    post_promotion_members: &VerifiedPostPromotionRecipients,
    post_promotion_trust: &TrustContext,
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
    enforce_key_not_expired_for_signing(&execution.key_ctx.expires_at)?;
    let ctx = RewrapArtifactExecutionContext::new(
        request,
        plan,
        &execution,
        post_promotion_members,
        post_promotion_trust,
    );
    execute_rewrap_artifacts(
        &ctx,
        confirm_known,
        confirm_non_member,
        confirm_recipients,
        confirm_recipient_set,
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_rewrap_execution_test.rs"]
mod tests;
