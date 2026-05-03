// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for rewrap commands.

use crate::app::context::execution::build_write_execution_warnings;
use crate::app::context::execution::ExecutionContext;
use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::review::review_recipient_trust_with_confirmation;
use crate::app::trust::TrustApprovalCandidate;
use crate::Result;
use std::path::PathBuf;

pub(crate) mod execution;
pub(crate) mod plan;
pub(crate) mod promotion;
pub(crate) mod trust;
pub(crate) mod types;

use self::promotion::PromotionReviewView;
use self::types::{
    IncomingPromotionCandidate, RewrapBatchOutcome, RewrapBatchRequest, RewrapTrustPlan,
};
use crate::app::context::options::CommonCommandOptions;

pub(crate) struct RewrapBatchCommandInput {
    pub options: CommonCommandOptions,
    pub execution: ExecutionContext,
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub explicit_targets: Vec<PathBuf>,
}

pub(crate) fn execute_rewrap_batch_command<
    EmitWarnings,
    ConfirmPromotions,
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
>(
    input: RewrapBatchCommandInput,
    mut emit_warnings: EmitWarnings,
    mut confirm_promotions: ConfirmPromotions,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
    confirm_recipients: ConfirmRecipients,
) -> Result<RewrapBatchOutcome>
where
    EmitWarnings: FnMut(&[String]),
    ConfirmPromotions: FnMut(&PromotionReviewView) -> Result<Vec<String>>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &std::path::Path) -> Result<bool>,
    ConfirmNonMember:
        FnMut(&TrustApprovalCandidate, &str, &[String], &std::path::Path) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    emit_warnings(&build_write_execution_warnings(&input.execution)?);
    let request = build_rewrap_batch_request(&input);
    let plan =
        plan::build_rewrap_batch_plan(&request.options, &input.execution, &input.explicit_targets)?;
    let accepted_promotions =
        collect_accepted_promotions(&plan, request.options.verbose, &mut confirm_promotions)?;
    let request = RewrapBatchRequest {
        accepted_promotions,
        ..request
    };
    let trust_plan =
        trust::build_rewrap_trust(&plan, &request.accepted_promotions, request.options.verbose)?;
    emit_warnings(&trust_plan.warnings);
    let approvals = review_rewrap_recipient_trust(&trust_plan, confirm_recipients)?;
    let mut outcome = execution::execute_confirmed_rewrap_batch(
        &request,
        &plan,
        &trust_plan.post_promotion_members,
        input.execution,
        &approvals,
        confirm_known,
        confirm_non_member,
    )?;
    emit_warnings(&outcome.warnings);
    outcome.warnings.clear();
    Ok(outcome)
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
    plan: &types::RewrapBatchPlan,
    verbose: bool,
    confirm_promotions: &mut ConfirmPromotions,
) -> Result<Vec<IncomingPromotionCandidate>>
where
    ConfirmPromotions: FnMut(&PromotionReviewView) -> Result<Vec<String>>,
{
    let Some(report) = plan.incoming_report.as_ref() else {
        return Ok(Vec::new());
    };
    let review_plan = promotion::build_promotion_review_plan(
        report,
        &plan.pre_promotion_trust.known_keys,
        &plan.pre_promotion_trust.self_trust,
        plan.pre_promotion_trust.is_interactive,
    )?;
    let session = promotion::build_promotion_review_session(&review_plan, verbose)?;
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
