// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::rewrap::types::RewrapInputTrustRequirement;
use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{RecipientTrustOutcome, SignerTrustOutcome, TrustApprovalCandidate};
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::Result;
use std::collections::BTreeSet;

use super::error::build_rewrap_rejection_error;
use super::online_verification::{
    review_candidate_for_confirmation, verify_trust_candidate_online, InteractiveTrustReviewKind,
};

#[derive(Clone, Copy)]
struct RewrapReviewLabels<'a> {
    context: &'a str,
    approval_subject: &'a str,
}

struct RewrapReviewState {
    approvals: Vec<ApprovedKnownKey>,
    seen_known: BTreeSet<KnownKeyIdentity>,
}

pub fn review_rewrap_input_trust_requirements_with_confirmation<
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
>(
    requirements: &[RewrapInputTrustRequirement],
    context_label: &str,
    approval_subject: &str,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
    confirm_recipients: ConfirmRecipients,
) -> Result<Vec<ApprovedKnownKey>>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    review_rewrap_input_trust_requirements_with_confirmation_verifier(
        requirements,
        context_label,
        approval_subject,
        |candidate| verify_trust_candidate_online(candidate, false),
        confirm_known,
        confirm_non_member,
        confirm_recipients,
    )
}

pub fn review_rewrap_input_trust_requirements_with_confirmation_verifier<
    VerifyOnline,
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
>(
    requirements: &[RewrapInputTrustRequirement],
    context_label: &str,
    approval_subject: &str,
    mut verify_online: VerifyOnline,
    mut confirm_known: ConfirmKnown,
    mut confirm_non_member: ConfirmNonMember,
    mut confirm_recipients: ConfirmRecipients,
) -> Result<Vec<ApprovedKnownKey>>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    let state = execute_rewrap_input_review(
        requirements,
        context_label,
        approval_subject,
        &mut verify_online,
        &mut confirm_known,
        &mut confirm_non_member,
        &mut confirm_recipients,
    )?;
    Ok(dedupe_approved_known_keys(state.approvals))
}

fn execute_rewrap_input_review<VerifyOnline, ConfirmKnown, ConfirmNonMember, ConfirmRecipients>(
    requirements: &[RewrapInputTrustRequirement],
    context_label: &str,
    approval_subject: &str,
    verify_online: &mut VerifyOnline,
    confirm_known: &mut ConfirmKnown,
    confirm_non_member: &mut ConfirmNonMember,
    confirm_recipients: &mut ConfirmRecipients,
) -> Result<RewrapReviewState>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    let mut state = RewrapReviewState {
        approvals: Vec::new(),
        seen_known: BTreeSet::new(),
    };
    review_rewrap_input_requirements(
        requirements,
        RewrapReviewLabels {
            context: context_label,
            approval_subject,
        },
        verify_online,
        confirm_known,
        confirm_non_member,
        confirm_recipients,
        &mut state,
    )?;
    Ok(state)
}

fn review_rewrap_input_requirements<
    VerifyOnline,
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
>(
    requirements: &[RewrapInputTrustRequirement],
    labels: RewrapReviewLabels<'_>,
    verify_online: &mut VerifyOnline,
    confirm_known: &mut ConfirmKnown,
    confirm_non_member: &mut ConfirmNonMember,
    confirm_recipients: &mut ConfirmRecipients,
    state: &mut RewrapReviewState,
) -> Result<()>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    for requirement in requirements {
        review_rewrap_input_requirement(
            requirement,
            labels,
            verify_online,
            confirm_known,
            confirm_non_member,
            confirm_recipients,
            state,
        )?;
    }
    Ok(())
}

fn review_rewrap_input_requirement<
    VerifyOnline,
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
>(
    requirement: &RewrapInputTrustRequirement,
    labels: RewrapReviewLabels<'_>,
    verify_online: &mut VerifyOnline,
    confirm_known: &mut ConfirmKnown,
    confirm_non_member: &mut ConfirmNonMember,
    confirm_recipients: &mut ConfirmRecipients,
    state: &mut RewrapReviewState,
) -> Result<()>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    review_rewrap_signer_requirement(
        requirement,
        labels,
        verify_online,
        confirm_known,
        confirm_non_member,
        &mut state.seen_known,
        &mut state.approvals,
    )?;
    review_rewrap_recipient_keys(
        requirement,
        labels,
        verify_online,
        confirm_recipients,
        &mut state.seen_known,
        &mut state.approvals,
    )
}

fn review_rewrap_signer_requirement<VerifyOnline, ConfirmKnown, ConfirmNonMember>(
    requirement: &RewrapInputTrustRequirement,
    labels: RewrapReviewLabels<'_>,
    verify_online: &mut VerifyOnline,
    confirm_known: &mut ConfirmKnown,
    confirm_non_member: &mut ConfirmNonMember,
    seen_known: &mut BTreeSet<KnownKeyIdentity>,
    approvals: &mut Vec<ApprovedKnownKey>,
) -> Result<()>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
{
    match &requirement.signer_outcome {
        SignerTrustOutcome::Accepted => Ok(()),
        SignerTrustOutcome::NeedsKnownKeyApproval(candidate) => review_rewrap_known_key(
            requirement,
            candidate,
            labels,
            verify_online,
            confirm_known,
            seen_known,
            approvals,
        ),
        SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate,
            current_recipients,
        } => review_rewrap_non_member(
            requirement,
            candidate,
            current_recipients,
            labels,
            verify_online,
            confirm_non_member,
        ),
    }
}

fn review_rewrap_known_key<VerifyOnline, ConfirmKnown>(
    requirement: &RewrapInputTrustRequirement,
    candidate: &TrustApprovalCandidate,
    labels: RewrapReviewLabels<'_>,
    verify_online: &mut VerifyOnline,
    confirm_known: &mut ConfirmKnown,
    seen_known: &mut BTreeSet<KnownKeyIdentity>,
    approvals: &mut Vec<ApprovedKnownKey>,
) -> Result<()>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
{
    let reviewed = review_candidate_for_confirmation(
        candidate,
        InteractiveTrustReviewKind::KnownKeyApproval,
        verify_online,
    )?;
    let approval = ApprovedKnownKey::from(&reviewed);
    if !seen_known.insert(KnownKeyIdentity::from(&approval)) {
        return Ok(());
    }
    if !confirm_known(&reviewed, labels.context)? {
        return Err(build_rewrap_rejection_error(
            &requirement.file_path,
            labels.approval_subject,
        ));
    }
    approvals.push(approval);
    Ok(())
}

fn review_rewrap_non_member<VerifyOnline, ConfirmNonMember>(
    requirement: &RewrapInputTrustRequirement,
    candidate: &TrustApprovalCandidate,
    current_recipients: &[String],
    labels: RewrapReviewLabels<'_>,
    verify_online: &mut VerifyOnline,
    confirm_non_member: &mut ConfirmNonMember,
) -> Result<()>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
{
    let reviewed = review_candidate_for_confirmation(
        candidate,
        InteractiveTrustReviewKind::NonMemberAcceptance,
        verify_online,
    )?;
    if confirm_non_member(&reviewed, labels.context, current_recipients)? {
        return Ok(());
    }
    Err(build_rewrap_rejection_error(
        &requirement.file_path,
        labels.approval_subject,
    ))
}

fn review_rewrap_recipient_keys<VerifyOnline, ConfirmRecipients>(
    requirement: &RewrapInputTrustRequirement,
    labels: RewrapReviewLabels<'_>,
    verify_online: &mut VerifyOnline,
    confirm_recipients: &mut ConfirmRecipients,
    seen_known: &mut BTreeSet<KnownKeyIdentity>,
    approvals: &mut Vec<ApprovedKnownKey>,
) -> Result<()>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    let RecipientTrustOutcome::NeedsManualApproval(candidates) = &requirement.recipient_outcome
    else {
        return Ok(());
    };
    let reviewed = collect_rewrap_recipient_key_reviews(candidates, verify_online, seen_known)?;
    if reviewed.is_empty() {
        return Ok(());
    }
    let approved = confirm_recipients(&reviewed, labels.context)?;
    if approved.len() != reviewed.len() {
        return Err(build_rewrap_rejection_error(
            &requirement.file_path,
            "recipient trust",
        ));
    }
    collect_rewrap_recipient_approvals(approved, seen_known, approvals);
    Ok(())
}

fn collect_rewrap_recipient_key_reviews<VerifyOnline>(
    candidates: &[TrustApprovalCandidate],
    verify_online: &mut VerifyOnline,
    seen_known: &BTreeSet<KnownKeyIdentity>,
) -> Result<Vec<TrustApprovalCandidate>>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
{
    candidates
        .iter()
        .filter(|candidate| {
            !seen_known.contains(&KnownKeyIdentity::new(
                candidate.member_handle.as_str(),
                candidate.kid.as_str(),
            ))
        })
        .map(|candidate| {
            review_candidate_for_confirmation(
                candidate,
                InteractiveTrustReviewKind::KnownKeyApproval,
                verify_online,
            )
        })
        .collect()
}

fn collect_rewrap_recipient_approvals(
    approved: Vec<TrustApprovalCandidate>,
    seen_known: &mut BTreeSet<KnownKeyIdentity>,
    approvals: &mut Vec<ApprovedKnownKey>,
) {
    for candidate in approved {
        let approval = ApprovedKnownKey::from(&candidate);
        seen_known.insert(KnownKeyIdentity::from(&approval));
        approvals.push(approval);
    }
}

fn dedupe_approved_known_keys(approvals: Vec<ApprovedKnownKey>) -> Vec<ApprovedKnownKey> {
    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();

    for approval in approvals {
        if seen.insert(KnownKeyIdentity::from(&approval)) {
            deduped.push(approval);
        }
    }

    deduped
}
