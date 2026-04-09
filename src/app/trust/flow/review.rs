// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::rewrap::types::RewrapSignerRequirement;
use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{RecipientTrustOutcome, SignerTrustOutcome, TrustApprovalCandidate};
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::{Error, Result};
use std::collections::BTreeSet;
use std::path::Path;

use super::online::{
    review_candidate_for_confirmation, verify_trust_candidate_online, InteractiveTrustReviewKind,
};
use super::persist::{build_rewrap_rejection_error, dedupe_approved_known_keys};

#[derive(Debug, Clone, Copy)]
pub(crate) struct SignerTrustLabels<'a> {
    pub(crate) context: &'a str,
    pub(crate) subject: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadSignerTrustReviewPlan<'a> {
    pub(crate) trust_outcome: &'a SignerTrustOutcome,
    pub(crate) labels: SignerTrustLabels<'a>,
    pub(crate) allow_non_member: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WriteRecipientTrustReviewPlan<'a> {
    pub(crate) signer_trust: Option<(&'a SignerTrustOutcome, SignerTrustLabels<'a>)>,
    pub(crate) recipient_trust: &'a RecipientTrustOutcome,
    pub(crate) recipient_context_label: &'a str,
}

#[allow(dead_code)]
pub(crate) fn review_signer_trust_with_handlers<ConfirmKnown, ConfirmNonMember>(
    outcome: &SignerTrustOutcome,
    context_label: &str,
    approval_subject: &str,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
) -> Result<Vec<ApprovedKnownKey>>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
{
    review_signer_trust_with_handlers_and_verifier(
        outcome,
        context_label,
        approval_subject,
        |candidate| verify_trust_candidate_online(candidate, false),
        confirm_known,
        confirm_non_member,
    )
}

pub(crate) fn review_signer_trust_with_handlers_and_verifier<
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
        SignerTrustOutcome::NeedsKnownKeyApproval(candidate) => {
            let reviewed = review_candidate_for_confirmation(
                candidate,
                InteractiveTrustReviewKind::KnownKeyApproval,
                &mut verify_online,
            )?;
            if confirm_known(&reviewed, context_label)? {
                Ok(vec![ApprovedKnownKey::from(&reviewed)])
            } else {
                Err(Error::Verify {
                    rule: "E_TRUST_APPROVAL_REJECTED".to_string(),
                    message: format!(
                        "Trust approval rejected for {} '{}' ({})",
                        approval_subject, reviewed.member_id, reviewed.kid
                    ),
                })
            }
        }
        SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate,
            current_recipients,
        } => {
            let reviewed = review_candidate_for_confirmation(
                candidate,
                InteractiveTrustReviewKind::NonMemberAcceptance,
                &mut verify_online,
            )?;
            if confirm_non_member(&reviewed, context_label, current_recipients)? {
                Ok(Vec::new())
            } else {
                Err(Error::Verify {
                    rule: "E_TRUST_NON_MEMBER_REJECTED".to_string(),
                    message: format!(
                        "Non-member acceptance rejected for {} '{}' ({})",
                        approval_subject, reviewed.member_id, reviewed.kid
                    ),
                })
            }
        }
    }
}

pub(crate) fn review_recipient_trust_with_handler<ConfirmRecipients>(
    outcome: &RecipientTrustOutcome,
    context_label: &str,
    confirm_recipients: ConfirmRecipients,
) -> Result<Vec<ApprovedKnownKey>>
where
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    review_recipient_trust_with_handler_and_verifier(
        outcome,
        context_label,
        |candidate| verify_trust_candidate_online(candidate, false),
        confirm_recipients,
    )
}

pub(crate) fn review_recipient_trust_with_handler_and_verifier<VerifyOnline, ConfirmRecipients>(
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
        RecipientTrustOutcome::NeedsManualApproval(candidates) => {
            let reviewed = candidates
                .iter()
                .map(|candidate| {
                    review_candidate_for_confirmation(
                        candidate,
                        InteractiveTrustReviewKind::KnownKeyApproval,
                        &mut verify_online,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            let approved = confirm_recipients(&reviewed, context_label)?;
            if approved.len() != reviewed.len() {
                return Err(Error::Verify {
                    rule: "E_TRUST_APPROVAL_REJECTED".to_string(),
                    message: "Trust approval rejected for one or more recipients".to_string(),
                });
            }
            Ok(approved.iter().map(ApprovedKnownKey::from).collect())
        }
    }
}

pub(crate) fn review_rewrap_signer_requirements_with_handlers<ConfirmKnown, ConfirmNonMember>(
    requirements: &[RewrapSignerRequirement],
    context_label: &str,
    approval_subject: &str,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
) -> Result<Vec<ApprovedKnownKey>>
where
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &Path) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String], &Path) -> Result<bool>,
{
    review_rewrap_signer_requirements_with_handlers_and_verifier(
        requirements,
        context_label,
        approval_subject,
        |candidate| verify_trust_candidate_online(candidate, false),
        confirm_known,
        confirm_non_member,
    )
}

pub(crate) fn review_rewrap_signer_requirements_with_handlers_and_verifier<
    VerifyOnline,
    ConfirmKnown,
    ConfirmNonMember,
>(
    requirements: &[RewrapSignerRequirement],
    context_label: &str,
    approval_subject: &str,
    mut verify_online: VerifyOnline,
    mut confirm_known: ConfirmKnown,
    mut confirm_non_member: ConfirmNonMember,
) -> Result<Vec<ApprovedKnownKey>>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &Path) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String], &Path) -> Result<bool>,
{
    let mut approvals = Vec::new();
    let mut seen_known = BTreeSet::new();

    for requirement in requirements {
        match &requirement.outcome {
            SignerTrustOutcome::Accepted => {}
            SignerTrustOutcome::NeedsKnownKeyApproval(candidate) => {
                let reviewed = review_candidate_for_confirmation(
                    candidate,
                    InteractiveTrustReviewKind::KnownKeyApproval,
                    &mut verify_online,
                )?;
                let approval = ApprovedKnownKey::from(&reviewed);
                if seen_known.insert(KnownKeyIdentity::from(&approval)) {
                    if !confirm_known(&reviewed, context_label, &requirement.file_path)? {
                        return Err(build_rewrap_rejection_error(
                            &requirement.file_path,
                            approval_subject,
                        ));
                    }
                    approvals.push(approval);
                }
            }
            SignerTrustOutcome::NeedsNonMemberAcceptance {
                candidate,
                current_recipients,
            } => {
                let reviewed = review_candidate_for_confirmation(
                    candidate,
                    InteractiveTrustReviewKind::NonMemberAcceptance,
                    &mut verify_online,
                )?;
                if !confirm_non_member(
                    &reviewed,
                    context_label,
                    current_recipients,
                    &requirement.file_path,
                )? {
                    return Err(build_rewrap_rejection_error(
                        &requirement.file_path,
                        approval_subject,
                    ));
                }
            }
        }
    }

    Ok(dedupe_approved_known_keys(approvals))
}

pub(crate) fn reject_non_member_read_trust(
    trust_outcome: &SignerTrustOutcome,
    approval_subject: &str,
) -> Result<()> {
    if let SignerTrustOutcome::NeedsNonMemberAcceptance { candidate, .. } = trust_outcome {
        return Err(Error::Verify {
            rule: "E_TRUST_NON_MEMBER".to_string(),
            message: format!(
                "Signer '{}' ({}) is not eligible for {} trust approval",
                candidate.member_id, candidate.kid, approval_subject
            ),
        });
    }
    Ok(())
}
