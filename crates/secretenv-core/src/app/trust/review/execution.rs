// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use std::collections::BTreeSet;

use crate::app::trust::{
    evaluate_output_recipient_set_trust, ArtifactRecipientTrustOutcome, CommandCapability,
    RecipientTrustOutcome, SignerTrustOutcome, TrustApprovalCandidate, TrustContext,
};
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::Result;

use super::persistence::{save_approved_known_keys, save_approved_recipient_set};
use super::recipient::review_recipient_trust_with_confirmation_verifier;
use super::signer::{
    enforce_read_trust_member_eligibility, review_signer_trust_with_confirmation_verifier,
};
use super::types::{ReadSignerTrustReviewPlan, WriteRecipientTrustReviewPlan};

#[derive(Clone, Copy)]
pub struct TrustExecutionContext<'a> {
    pub options: &'a CommonCommandOptions,
    pub execution: &'a ExecutionContext,
    pub warnings: &'a [String],
}

pub fn execute_read_with_signer_trust<
    T,
    EmitWarnings,
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    Execute,
>(
    execution: TrustExecutionContext<'_>,
    trust_plan: ReadSignerTrustReviewPlan<'_>,
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
    if !trust_plan.allow_non_member {
        enforce_read_trust_member_eligibility(trust_plan.trust_outcome, trust_plan.labels.subject)?;
    }
    let approvals = review_read_key_trust_with_confirmation_verifier(
        ReadKeyTrustReview {
            signer_outcome: trust_plan.trust_outcome,
            recipient_outcome: trust_plan.recipient_trust_outcome,
            context_label: trust_plan.labels.context,
            approval_subject: trust_plan.labels.subject,
        },
        execution.options.debug,
        confirm_known,
        confirm_non_member,
        confirm_recipients,
    )?;
    save_approved_known_keys(execution, &approvals, &mut emit_warnings)?;
    let result = execute()?;
    Ok(result)
}

struct ReadKeyTrustReview<'a> {
    signer_outcome: &'a SignerTrustOutcome,
    recipient_outcome: &'a RecipientTrustOutcome,
    context_label: &'a str,
    approval_subject: &'a str,
}

fn review_read_key_trust_with_confirmation_verifier<
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
>(
    review: ReadKeyTrustReview<'_>,
    verbose: bool,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
    confirm_recipients: ConfirmRecipients,
) -> Result<Vec<crate::app::trust::approval::ApprovedKnownKey>>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    let mut approvals = Vec::new();
    if matches!(
        review.signer_outcome,
        SignerTrustOutcome::NeedsNonMemberAcceptance { .. }
    ) {
        approvals.extend(review_signer_trust_with_confirmation_verifier(
            review.signer_outcome,
            review.context_label,
            review.approval_subject,
            |candidate| {
                super::online_verification::verify_trust_candidate_online(candidate, verbose)
            },
            confirm_known,
            confirm_non_member,
        )?);
    }

    let candidates = collect_read_key_candidates(review.signer_outcome, review.recipient_outcome);
    approvals.extend(review_recipient_trust_with_confirmation_verifier(
        &build_read_key_outcome(candidates),
        review.context_label,
        |candidate| super::online_verification::verify_trust_candidate_online(candidate, verbose),
        confirm_recipients,
    )?);
    Ok(approvals)
}

fn collect_read_key_candidates(
    signer_outcome: &SignerTrustOutcome,
    recipient_outcome: &RecipientTrustOutcome,
) -> Vec<TrustApprovalCandidate> {
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();
    if let SignerTrustOutcome::NeedsKnownKeyApproval(candidate) = signer_outcome {
        push_unique_candidate(&mut candidates, &mut seen, candidate);
    }
    if let RecipientTrustOutcome::NeedsManualApproval(recipient_candidates) = recipient_outcome {
        for candidate in recipient_candidates {
            push_unique_candidate(&mut candidates, &mut seen, candidate);
        }
    }
    candidates
}

fn push_unique_candidate(
    candidates: &mut Vec<TrustApprovalCandidate>,
    seen: &mut BTreeSet<String>,
    candidate: &TrustApprovalCandidate,
) {
    if seen.insert(candidate.kid.to_string()) {
        candidates.push(candidate.clone());
    }
}

fn build_read_key_outcome(candidates: Vec<TrustApprovalCandidate>) -> RecipientTrustOutcome {
    if candidates.is_empty() {
        RecipientTrustOutcome::Accepted
    } else {
        RecipientTrustOutcome::NeedsManualApproval(candidates)
    }
}

pub fn review_and_save_artifact_recipient_set<EmitWarnings, ConfirmRecipientSet>(
    execution: TrustExecutionContext<'_>,
    outcome: &ArtifactRecipientTrustOutcome,
    context_label: &str,
    emit_warnings: &mut EmitWarnings,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<()>
where
    EmitWarnings: FnMut(&[String]),
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let approval =
        review_artifact_recipient_set_trust(outcome, context_label, confirm_recipient_set)?;
    save_approved_recipient_set(execution, approval, emit_warnings)
}

pub struct ArtifactRecipientSetReviewInput<'a> {
    pub trust_ctx: &'a TrustContext,
    pub recipient_set: &'a ArtifactRecipientSet,
    pub capability: CommandCapability,
    pub context_label: &'a str,
}

pub fn review_artifact_recipient_set_output<EmitWarnings, ConfirmRecipientSet>(
    execution: TrustExecutionContext<'_>,
    review: ArtifactRecipientSetReviewInput<'_>,
    emit_warnings: &mut EmitWarnings,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<()>
where
    EmitWarnings: FnMut(&[String]),
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let outcome = evaluate_output_recipient_set_trust(
        review.trust_ctx,
        review.recipient_set,
        review.capability,
    )?;
    review_and_save_artifact_recipient_set(
        execution,
        &outcome,
        review.context_label,
        emit_warnings,
        confirm_recipient_set,
    )
}

pub fn execute_write_with_recipient_trust<
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
                    execution.options.debug,
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
                execution.options.debug,
            )
        },
        confirm_recipients,
    )?);
    save_approved_known_keys(execution, &approvals, &mut emit_warnings)?;
    let result = execute()?;
    Ok(result)
}

pub fn review_artifact_recipient_set_trust<ConfirmRecipientSet>(
    outcome: &ArtifactRecipientTrustOutcome,
    context_label: &str,
    mut confirm: ConfirmRecipientSet,
) -> Result<Option<ArtifactRecipientSet>>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    match outcome {
        ArtifactRecipientTrustOutcome::Accepted
        | ArtifactRecipientTrustOutcome::SkippedStrictKeyCheckingNo => Ok(None),
        ArtifactRecipientTrustOutcome::NeedsManualApproval(review) => {
            if confirm(outcome, context_label)? {
                Ok(Some(review.current_set().clone()))
            } else {
                Err(crate::Error::build_invalid_operation_error(
                    "Recipient set approval declined".to_string(),
                ))
            }
        }
    }
}
