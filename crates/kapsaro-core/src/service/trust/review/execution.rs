// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust review orchestration around a read or write.
//! Runs the operation, collects review requests and saves what was approved.

use std::collections::BTreeSet;

use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::service::trust::approval::{
    observe_recipient_set_approval_store, save_reviewed_recipient_set_approval, ApprovedKnownKey,
};
use crate::service::trust::{
    evaluate_output_recipient_set_trust, ArtifactRecipientTrustOutcome, RecipientTrustOutcome,
    SignerTrustOutcome, TrustApprovalCandidate, TrustCommandSession, TrustContext,
};
use crate::Result;

use super::persistence::save_approved_known_key_documents;
use super::recipient::review_recipient_trust_with_confirmation_verifier;
use super::signer::{
    enforce_read_trust_member_eligibility, review_signer_trust_with_confirmation_verifier,
};
use super::types::{ReadSignerTrustReviewPlan, WriteRecipientTrustReviewPlan};

/// A review that reports what the operation already found before it prompts.
///
/// Only the entry points that gate a whole command carry warnings; a review of
/// one artifact's recipient set has none to report and says so by taking the
/// capabilities alone.
#[derive(Clone, Copy)]
pub struct TrustReviewContext<'a> {
    pub trust: &'a TrustCommandSession,
    pub warnings: &'a [String],
}

/// The three confirmations one read's key trust review asks its caller for.
///
/// A single review pass may reach any of them, and which one it reaches depends
/// on what the trust state turned out to be. Carrying them together means a
/// caller supplies the whole set once instead of three positional callbacks a
/// later signature change could silently reorder.
pub struct ReadTrustConfirmations<ConfirmKnown, ConfirmNonMember, ConfirmRecipients>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    /// Approve a signer key the local trust store does not yet know.
    pub known_key: ConfirmKnown,
    /// Accept a signer who is not a workspace member.
    pub non_member_signer: ConfirmNonMember,
    /// Choose which of the artifact's recipient keys to approve.
    pub recipients: ConfirmRecipients,
}

pub fn execute_read_with_signer_trust<T, ConfirmKnown, ConfirmNonMember, ConfirmRecipients>(
    review_context: TrustReviewContext<'_>,
    trust_plan: ReadSignerTrustReviewPlan<'_>,
    mut emit_warnings: impl FnMut(&[String]),
    confirmations: ReadTrustConfirmations<ConfirmKnown, ConfirmNonMember, ConfirmRecipients>,
    execute: impl FnOnce() -> Result<T>,
) -> Result<T>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    emit_warnings(review_context.warnings);
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
        confirmations.known_key,
        confirmations.non_member_signer,
        confirmations.recipients,
    )?;
    save_approved_known_key_documents(review_context.trust, &approvals)?;
    execute()
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
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
    confirm_recipients: ConfirmRecipients,
) -> Result<Vec<crate::service::trust::approval::ApprovedKnownKey>>
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
            super::online_verification::verify_trust_candidate_online,
            confirm_known,
            confirm_non_member,
        )?);
    }

    let candidates = collect_read_key_candidates(review.signer_outcome, review.recipient_outcome);
    approvals.extend(review_recipient_trust_with_confirmation_verifier(
        &build_recipient_key_outcome(candidates),
        review.context_label,
        super::online_verification::verify_trust_candidate_online,
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
    if seen.insert(candidate.kid().to_string()) {
        candidates.push(candidate.clone());
    }
}

fn build_recipient_key_outcome(candidates: Vec<TrustApprovalCandidate>) -> RecipientTrustOutcome {
    if candidates.is_empty() {
        RecipientTrustOutcome::Accepted
    } else {
        RecipientTrustOutcome::NeedsManualApproval(candidates)
    }
}

/// Ask the operator about one artifact's recipient set and store what they
/// agreed to, bound to the trust store the decision was made against.
///
/// The store is observed before the prompt, so the record this write replaces
/// is the one the operator was shown. An outcome that needs no approval reaches
/// the trust store not at all.
pub fn review_and_save_artifact_recipient_set<ConfirmRecipientSet>(
    session: &TrustCommandSession,
    outcome: &ArtifactRecipientTrustOutcome,
    context_label: &str,
    mut confirm_recipient_set: ConfirmRecipientSet,
) -> Result<()>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let ArtifactRecipientTrustOutcome::NeedsManualApproval(review) = outcome else {
        return Ok(());
    };
    let observed = observe_recipient_set_approval_store(session)?;
    if !confirm_recipient_set(outcome, context_label)? {
        return Err(crate::Error::build_invalid_operation_error(
            "Recipient set approval declined".to_string(),
        ));
    }
    save_reviewed_recipient_set_approval(session, observed.as_ref(), review.current_set().clone())
        .map(|_| ())
}

pub struct ArtifactRecipientSetReviewInput<'a> {
    pub trust_ctx: &'a TrustContext,
    pub recipient_set: &'a ArtifactRecipientSet,
    pub context_label: &'a str,
}

pub fn review_artifact_recipient_set_output<ConfirmRecipientSet>(
    session: &TrustCommandSession,
    review: ArtifactRecipientSetReviewInput<'_>,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<()>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let evaluator = crate::service::trust::snapshot::load_trust_policy_evaluator(
        session,
        review.trust_ctx.active_members_by_kid.clone(),
    )?;
    let outcome = evaluate_output_recipient_set_trust(
        &evaluator,
        session.key_ctx(),
        review.trust_ctx,
        review.recipient_set,
    )?;
    review_and_save_artifact_recipient_set(
        session,
        &outcome,
        review.context_label,
        confirm_recipient_set,
    )
}

pub fn review_write_recipient_trust<
    EmitWarnings,
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
>(
    review_context: TrustReviewContext<'_>,
    trust_plan: WriteRecipientTrustReviewPlan<'_>,
    mut emit_warnings: EmitWarnings,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
    confirm_recipients: ConfirmRecipients,
) -> Result<()>
where
    EmitWarnings: FnMut(&[String]),
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    emit_warnings(review_context.warnings);
    let mut approvals = review_write_signer_trust_with_confirmation_verifier(
        trust_plan,
        confirm_known,
        confirm_non_member,
    )?;
    approvals.extend(review_write_recipient_trust_with_confirmation_verifier(
        trust_plan,
        approvals.as_slice(),
        confirm_recipients,
    )?);
    save_approved_known_key_documents(review_context.trust, &approvals)?;
    Ok(())
}

fn review_write_signer_trust_with_confirmation_verifier<ConfirmKnown, ConfirmNonMember>(
    trust_plan: WriteRecipientTrustReviewPlan<'_>,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
) -> Result<Vec<ApprovedKnownKey>>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
{
    let Some((trust_outcome, labels)) = trust_plan.signer_trust else {
        return Ok(Vec::new());
    };
    review_signer_trust_with_confirmation_verifier(
        trust_outcome,
        labels.context,
        labels.subject,
        super::online_verification::verify_trust_candidate_online,
        confirm_known,
        confirm_non_member,
    )
}

fn review_write_recipient_trust_with_confirmation_verifier<ConfirmRecipients>(
    trust_plan: WriteRecipientTrustReviewPlan<'_>,
    approved_keys: &[ApprovedKnownKey],
    confirm_recipients: ConfirmRecipients,
) -> Result<Vec<ApprovedKnownKey>>
where
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    let recipient_trust =
        build_write_recipient_key_outcome(trust_plan.recipient_trust, approved_keys);
    review_recipient_trust_with_confirmation_verifier(
        &recipient_trust,
        trust_plan.recipient_context_label,
        super::online_verification::verify_trust_candidate_online,
        confirm_recipients,
    )
}

fn build_write_recipient_key_outcome(
    recipient_trust: &RecipientTrustOutcome,
    approved_keys: &[ApprovedKnownKey],
) -> RecipientTrustOutcome {
    let RecipientTrustOutcome::NeedsManualApproval(candidates) = recipient_trust else {
        return RecipientTrustOutcome::Accepted;
    };
    let candidates = candidates
        .iter()
        .filter(|candidate| !is_approved_candidate(candidate, approved_keys))
        .cloned()
        .collect();
    build_recipient_key_outcome(candidates)
}

fn is_approved_candidate(
    candidate: &TrustApprovalCandidate,
    approved_keys: &[ApprovedKnownKey],
) -> bool {
    approved_keys.iter().any(|approval| {
        approval.member_handle() == candidate.member_handle() && approval.kid() == candidate.kid()
    })
}
