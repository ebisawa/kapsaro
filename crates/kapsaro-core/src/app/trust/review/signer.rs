// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Reviews a signer trust outcome, routing known-key approvals and non-member
//! acceptances through confirmation callbacks and rejecting non-members where ineligible.

use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{SignerTrustOutcome, TrustApprovalCandidate};
use crate::{Error, Result};

use super::error::{build_non_member_rejection_error, build_trust_approval_rejection_error};
use super::online_verification::{review_candidate_for_confirmation, InteractiveTrustReviewKind};

pub fn review_signer_trust_with_confirmation_verifier<
    VerifyOnline,
    ConfirmKnown,
    ConfirmNonMember,
>(
    outcome: &SignerTrustOutcome,
    context_label: &str,
    approval_subject: &str,
    mut verify_online: VerifyOnline,
    mut confirm_known: ConfirmKnown,
    mut confirm_non_member: ConfirmNonMember,
) -> Result<Vec<ApprovedKnownKey>>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
{
    match outcome {
        SignerTrustOutcome::Accepted => Ok(Vec::new()),
        SignerTrustOutcome::NeedsKnownKeyApproval(candidate) => review_known_key_approval(
            candidate,
            context_label,
            approval_subject,
            &mut verify_online,
            &mut confirm_known,
        ),
        SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate,
            current_recipients,
        } => review_non_member_acceptance(
            candidate,
            current_recipients,
            context_label,
            approval_subject,
            &mut verify_online,
            &mut confirm_non_member,
        ),
    }
}

pub fn enforce_read_trust_member_eligibility(
    trust_outcome: &SignerTrustOutcome,
    approval_subject: &str,
) -> Result<()> {
    if let SignerTrustOutcome::NeedsNonMemberAcceptance { candidate, .. } = trust_outcome {
        return Err(Error::build_verification_error(
            "E_TRUST_NON_MEMBER".to_string(),
            format!(
                "Signer '{}' ({}) is not eligible for {} trust approval",
                candidate.member_handle(),
                candidate.kid(),
                approval_subject
            ),
        ));
    }
    Ok(())
}

fn review_known_key_approval<VerifyOnline, ConfirmKnown>(
    candidate: &TrustApprovalCandidate,
    context_label: &str,
    approval_subject: &str,
    verify_online: &mut VerifyOnline,
    confirm_known: &mut ConfirmKnown,
) -> Result<Vec<ApprovedKnownKey>>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
{
    let reviewed = review_candidate_for_confirmation(
        candidate,
        InteractiveTrustReviewKind::KnownKeyApproval,
        verify_online,
    )?;
    if confirm_known(&reviewed, context_label)? {
        return Ok(vec![ApprovedKnownKey::from_candidate(&reviewed)?]);
    }
    Err(build_trust_approval_rejection_error(
        approval_subject,
        &reviewed,
    ))
}

fn review_non_member_acceptance<VerifyOnline, ConfirmNonMember>(
    candidate: &TrustApprovalCandidate,
    current_recipients: &[String],
    context_label: &str,
    approval_subject: &str,
    verify_online: &mut VerifyOnline,
    confirm_non_member: &mut ConfirmNonMember,
) -> Result<Vec<ApprovedKnownKey>>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
{
    let reviewed = review_candidate_for_confirmation(
        candidate,
        InteractiveTrustReviewKind::NonMemberAcceptance,
        verify_online,
    )?;
    if confirm_non_member(&reviewed, context_label, current_recipients)? {
        return Ok(Vec::new());
    }
    Err(build_non_member_rejection_error(
        approval_subject,
        &reviewed,
    ))
}
