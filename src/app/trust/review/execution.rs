// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::TrustApprovalCandidate;
use crate::Result;

use super::persistence::save_approved_known_keys;
use super::recipient::review_recipient_trust_with_confirmation_verifier;
use super::signer::{
    enforce_read_trust_member_eligibility, review_signer_trust_with_confirmation_verifier,
};
use super::types::{ReadSignerTrustReviewPlan, WriteRecipientTrustReviewPlan};

#[derive(Clone, Copy)]
pub(crate) struct TrustExecutionContext<'a> {
    pub(crate) options: &'a CommonCommandOptions,
    pub(crate) execution: &'a ExecutionContext,
    pub(crate) warnings: &'a [String],
}

pub(crate) fn execute_read_with_signer_trust<
    T,
    EmitWarnings,
    ConfirmKnown,
    ConfirmNonMember,
    Execute,
>(
    execution: TrustExecutionContext<'_>,
    trust_plan: ReadSignerTrustReviewPlan<'_>,
    mut emit_warnings: EmitWarnings,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
    execute: Execute,
) -> Result<T>
where
    EmitWarnings: FnMut(&[String]),
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    Execute: FnOnce() -> Result<T>,
{
    emit_warnings(execution.warnings);
    if !trust_plan.allow_non_member {
        enforce_read_trust_member_eligibility(trust_plan.trust_outcome, trust_plan.labels.subject)?;
    }
    let approvals = review_signer_trust_with_confirmation_verifier(
        trust_plan.trust_outcome,
        trust_plan.labels.context,
        trust_plan.labels.subject,
        |candidate| {
            super::online_verification::verify_trust_candidate_online(
                candidate,
                execution.options.verbose,
            )
        },
        confirm_known,
        confirm_non_member,
    )?;
    let result = execute()?;
    save_approved_known_keys(execution, &approvals, &mut emit_warnings)?;
    Ok(result)
}

pub(crate) fn execute_write_with_recipient_trust<
    T,
    EmitWarnings,
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    Execute,
>(
    execution: TrustExecutionContext<'_>,
    trust_plan: WriteRecipientTrustReviewPlan<'_>,
    mut emit_warnings: EmitWarnings,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
    confirm_recipients: ConfirmRecipients,
    execute: Execute,
) -> Result<T>
where
    EmitWarnings: FnMut(&[String]),
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
    Execute: FnOnce() -> Result<T>,
{
    emit_warnings(execution.warnings);
    let mut approvals = match trust_plan.signer_trust {
        Some((trust_outcome, labels)) => review_signer_trust_with_confirmation_verifier(
            trust_outcome,
            labels.context,
            labels.subject,
            |candidate| {
                super::online_verification::verify_trust_candidate_online(
                    candidate,
                    execution.options.verbose,
                )
            },
            confirm_known,
            confirm_non_member,
        )?,
        None => Vec::new(),
    };
    approvals.extend(review_recipient_trust_with_confirmation_verifier(
        trust_plan.recipient_trust,
        trust_plan.recipient_context_label,
        |candidate| {
            super::online_verification::verify_trust_candidate_online(
                candidate,
                execution.options.verbose,
            )
        },
        confirm_recipients,
    )?);
    let result = execute()?;
    save_approved_known_keys(execution, &approvals, &mut emit_warnings)?;
    Ok(result)
}
