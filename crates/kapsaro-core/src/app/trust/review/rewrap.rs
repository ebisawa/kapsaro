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
    let mut approvals = Vec::new();
    let mut seen_known = BTreeSet::new();
    let labels = RewrapReviewLabels {
        context: context_label,
        approval_subject,
    };

    for requirement in requirements {
        match &requirement.signer_outcome {
            SignerTrustOutcome::Accepted => {}
            SignerTrustOutcome::NeedsKnownKeyApproval(candidate) => {
                review_rewrap_known_key(
                    requirement,
                    candidate,
                    labels,
                    &mut verify_online,
                    &mut confirm_known,
                    &mut seen_known,
                    &mut approvals,
                )?;
            }
            SignerTrustOutcome::NeedsNonMemberAcceptance {
                candidate,
                current_recipients,
            } => {
                review_rewrap_non_member(
                    requirement,
                    candidate,
                    current_recipients,
                    labels,
                    &mut verify_online,
                    &mut confirm_non_member,
                )?;
            }
        }
        review_rewrap_recipient_keys(
            requirement,
            labels,
            &mut verify_online,
            &mut confirm_recipients,
            &mut seen_known,
            &mut approvals,
        )?;
    }

    Ok(dedupe_approved_known_keys(approvals))
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
    let reviewed = candidates
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
        .collect::<Result<Vec<_>>>()?;
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
    for candidate in approved {
        let approval = ApprovedKnownKey::from(&candidate);
        seen_known.insert(KnownKeyIdentity::from(&approval));
        approvals.push(approval);
    }
    Ok(())
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
