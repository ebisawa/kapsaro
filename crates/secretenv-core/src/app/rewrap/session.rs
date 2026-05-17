// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Review-time session assembly for rewrap commands.

use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::review::review_recipient_trust_with_confirmation;
use crate::app::trust::{TrustApprovalCandidate, TrustContext};
use crate::model::public_key::PublicKey;
use crate::Result;

use super::promotion::PromotionReviewView;
use super::types::{
    IncomingPromotionCandidate, RewrapBatchPlan, RewrapBatchRequest, RewrapTrustPlan,
};
use super::RewrapBatchCommandInput;

pub struct RewrapReviewSession {
    pub request: RewrapBatchRequest,
    pub plan: RewrapBatchPlan,
    pub expected_post_promotion_members: Vec<PublicKey>,
    pub post_promotion_trust: TrustContext,
    pub approvals: Vec<ApprovedKnownKey>,
    pub review_warnings: Vec<String>,
}

pub fn build_rewrap_review_session<ConfirmPromotions, ConfirmRecipients>(
    input: &RewrapBatchCommandInput,
    confirm_promotions: &mut ConfirmPromotions,
    confirm_recipients: ConfirmRecipients,
) -> Result<RewrapReviewSession>
where
    ConfirmPromotions: FnMut(&PromotionReviewView) -> Result<Vec<String>>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    let request = build_rewrap_batch_request(input);
    let plan = super::plan::build_rewrap_batch_plan(
        &request.options,
        &input.execution,
        &input.explicit_targets,
    )?;
    let accepted_promotions =
        collect_accepted_promotions(&plan, request.options.debug, confirm_promotions)?;
    let request = RewrapBatchRequest {
        accepted_promotions,
        ..request
    };
    let trust_plan = super::trust::build_rewrap_trust(
        &plan,
        &request.accepted_promotions,
        request.options.debug,
    )?;
    let approvals = review_rewrap_recipient_trust(&trust_plan, confirm_recipients)?;
    let post_promotion_trust = super::trust::build_post_promotion_trust_context(
        &plan.pre_promotion_trust,
        &trust_plan.post_promotion_members,
    )?;
    Ok(RewrapReviewSession {
        request,
        plan,
        expected_post_promotion_members: trust_plan.post_promotion_members,
        post_promotion_trust,
        approvals,
        review_warnings: trust_plan.warnings,
    })
}

fn build_rewrap_batch_request(input: &RewrapBatchCommandInput) -> RewrapBatchRequest {
    RewrapBatchRequest {
        options: input.options.clone(),
        rotate_key: input.rotate_key,
        clear_disclosure_history: input.clear_disclosure_history,
        accepted_promotions: Vec::new(),
    }
}

fn collect_accepted_promotions<ConfirmPromotions>(
    plan: &RewrapBatchPlan,
    verbose: bool,
    confirm_promotions: &mut ConfirmPromotions,
) -> Result<Vec<IncomingPromotionCandidate>>
where
    ConfirmPromotions: FnMut(&PromotionReviewView) -> Result<Vec<String>>,
{
    let Some(report) = plan.incoming_report.as_ref() else {
        return Ok(Vec::new());
    };
    let review_plan = super::promotion::build_promotion_review_plan(
        report,
        &plan.pre_promotion_trust.known_keys,
        &plan.pre_promotion_trust.self_trust,
        plan.pre_promotion_trust.is_interactive,
    )?;
    let session = super::promotion::build_promotion_review_session(&review_plan, verbose)?;
    let accepted_member_handles = confirm_promotions(session.view())?;
    Ok(session.into_accepted_candidates(&accepted_member_handles))
}

fn review_rewrap_recipient_trust<ConfirmRecipients>(
    trust_plan: &RewrapTrustPlan,
    confirm_recipients: ConfirmRecipients,
) -> Result<Vec<ApprovedKnownKey>>
where
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    let mut approvals = review_recipient_trust_with_confirmation(
        &trust_plan.recipient_trust,
        "rewrap recipients",
        confirm_recipients,
    )?;
    approvals.extend(trust_plan.accepted_promotion_candidates.clone());
    Ok(approvals)
}
