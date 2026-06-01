// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{RecipientTrustOutcome, TrustApprovalCandidate};
use crate::{Error, Result};

use super::online_verification::{
    review_candidate_for_confirmation, verify_trust_candidate_online, InteractiveTrustReviewKind,
};

pub fn review_recipient_trust_with_confirmation<ConfirmRecipients>(
    outcome: &RecipientTrustOutcome,
    context_label: &str,
    confirm_recipients: ConfirmRecipients,
) -> Result<Vec<ApprovedKnownKey>>
where
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    review_recipient_trust_with_confirmation_verifier(
        outcome,
        context_label,
        |candidate| verify_trust_candidate_online(candidate, false),
        confirm_recipients,
    )
}

pub fn review_recipient_trust_with_confirmation_verifier<VerifyOnline, ConfirmRecipients>(
    outcome: &RecipientTrustOutcome,
    context_label: &str,
    mut verify_online: VerifyOnline,
    mut confirm_recipients: ConfirmRecipients,
) -> Result<Vec<ApprovedKnownKey>>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    match outcome {
        RecipientTrustOutcome::Accepted => Ok(Vec::new()),
        RecipientTrustOutcome::NeedsManualApproval(candidates) => review_recipient_approvals(
            candidates,
            context_label,
            &mut verify_online,
            &mut confirm_recipients,
        ),
    }
}

fn review_recipient_approvals<VerifyOnline, ConfirmRecipients>(
    candidates: &[TrustApprovalCandidate],
    context_label: &str,
    verify_online: &mut VerifyOnline,
    confirm_recipients: &mut ConfirmRecipients,
) -> Result<Vec<ApprovedKnownKey>>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    let reviewed = candidates
        .iter()
        .map(|candidate| {
            review_candidate_for_confirmation(
                candidate,
                InteractiveTrustReviewKind::KnownKeyApproval,
                verify_online,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let approved = confirm_recipients(&reviewed, context_label)?;
    if approved.len() != reviewed.len() {
        return Err(Error::build_verification_error(
            "E_TRUST_APPROVAL_REJECTED".to_string(),
            "Trust approval rejected for one or more recipients".to_string(),
        ));
    }
    Ok(approved.iter().map(ApprovedKnownKey::from).collect())
}
