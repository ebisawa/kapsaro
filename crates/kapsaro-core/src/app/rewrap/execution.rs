// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::trust::review::{save_approved_known_key_warnings, TrustExecutionContext};
use crate::app::trust::{ArtifactRecipientTrustOutcome, TrustApprovalCandidate};
use crate::Result;

use super::artifact::{execute_rewrap_artifacts, RewrapArtifactExecutionContext};
use super::session::RewrapReviewSession;
use super::snapshot::{load_verified_post_promotion_members, promote_accepted_incoming_members};
use super::types::{
    RewrapBatchOutcome, RewrapBatchPlan, RewrapBatchRequest, VerifiedPostPromotionRecipients,
};
use crate::app::trust::TrustContext;

struct ConfirmedRewrapContext {
    promoted_member_handles: Vec<String>,
    post_promotion_members: VerifiedPostPromotionRecipients,
    approval_warnings: Vec<String>,
}

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
    let confirmed = resolve_confirmed_rewrap_context(&review_session, &execution)?;
    let outcome = execute_confirmed_artifact_rewrites(
        &review_session,
        execution,
        &confirmed.post_promotion_members,
        &mut confirm_known,
        &mut confirm_non_member,
        &mut confirm_recipients,
        &mut confirm_recipient_set,
    )?;
    Ok(build_confirmed_rewrap_outcome(outcome, confirmed))
}

fn resolve_confirmed_rewrap_context(
    review_session: &RewrapReviewSession,
    execution: &ExecutionContext,
) -> Result<ConfirmedRewrapContext> {
    Ok(ConfirmedRewrapContext {
        promoted_member_handles: execute_accepted_member_promotions(review_session)?,
        post_promotion_members: load_actual_post_promotion_members(review_session)?,
        approval_warnings: save_rewrap_approval_warnings(review_session, execution)?,
    })
}

fn execute_confirmed_artifact_rewrites<
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    ConfirmRecipientSet,
>(
    review_session: &RewrapReviewSession,
    execution: ExecutionContext,
    post_promotion_members: &VerifiedPostPromotionRecipients,
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
    execute_reviewed_rewrap_artifacts(
        &review_session.request,
        &review_session.plan,
        execution,
        post_promotion_members,
        &review_session.post_promotion_trust,
        confirm_known,
        confirm_non_member,
        confirm_recipients,
        confirm_recipient_set,
    )
}

fn execute_accepted_member_promotions(review_session: &RewrapReviewSession) -> Result<Vec<String>> {
    promote_accepted_incoming_members(
        &review_session.plan.workspace_root,
        &review_session.request.accepted_promotions,
    )
}

fn load_actual_post_promotion_members(
    review_session: &RewrapReviewSession,
) -> Result<VerifiedPostPromotionRecipients> {
    load_verified_post_promotion_members(
        &review_session.plan.workspace_root,
        &review_session.expected_post_promotion_members,
    )
}

fn save_rewrap_approval_warnings(
    review_session: &RewrapReviewSession,
    execution: &ExecutionContext,
) -> Result<Vec<String>> {
    execution.key_ctx.enforce_signing_key_not_expired()?;
    save_approved_known_key_warnings(
        TrustExecutionContext {
            options: &review_session.request.options,
            execution,
            warnings: &[],
        },
        &review_session.approvals,
    )
}

fn build_confirmed_rewrap_outcome(
    mut outcome: RewrapBatchOutcome,
    confirmed: ConfirmedRewrapContext,
) -> RewrapBatchOutcome {
    let mut approval_warnings = confirmed.approval_warnings;
    outcome.promoted_member_handles = confirmed.promoted_member_handles;
    approval_warnings.extend(outcome.warnings);
    outcome.warnings = approval_warnings;
    outcome
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
    execution.key_ctx.enforce_signing_key_not_expired()?;
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
