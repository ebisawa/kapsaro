// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::path::Path;

use crate::app::rewrap::types::RewrapSignerRequirement;
use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{SignerTrustOutcome, TrustApprovalCandidate};
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::Result;

use super::error::build_rewrap_rejection_error;
use super::online_verification::{
    review_candidate_for_confirmation, verify_trust_candidate_online, InteractiveTrustReviewKind,
};

#[derive(Clone, Copy)]
struct RewrapReviewLabels<'a> {
    context: &'a str,
    approval_subject: &'a str,
}

pub(crate) fn review_rewrap_signer_requirements_with_confirmation<ConfirmKnown, ConfirmNonMember>(
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
    review_rewrap_signer_requirements_with_confirmation_verifier(
        requirements,
        context_label,
        approval_subject,
        |candidate| verify_trust_candidate_online(candidate, false),
        confirm_known,
        confirm_non_member,
    )
}

pub(crate) fn review_rewrap_signer_requirements_with_confirmation_verifier<
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
    let labels = RewrapReviewLabels {
        context: context_label,
        approval_subject,
    };

    for requirement in requirements {
        match &requirement.outcome {
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
    }

    Ok(dedupe_approved_known_keys(approvals))
}

fn review_rewrap_known_key<VerifyOnline, ConfirmKnown>(
    requirement: &RewrapSignerRequirement,
    candidate: &TrustApprovalCandidate,
    labels: RewrapReviewLabels<'_>,
    verify_online: &mut VerifyOnline,
    confirm_known: &mut ConfirmKnown,
    seen_known: &mut BTreeSet<KnownKeyIdentity>,
    approvals: &mut Vec<ApprovedKnownKey>,
) -> Result<()>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &Path) -> Result<bool>,
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
    if !confirm_known(&reviewed, labels.context, &requirement.file_path)? {
        return Err(build_rewrap_rejection_error(
            &requirement.file_path,
            labels.approval_subject,
        ));
    }
    approvals.push(approval);
    Ok(())
}

fn review_rewrap_non_member<VerifyOnline, ConfirmNonMember>(
    requirement: &RewrapSignerRequirement,
    candidate: &TrustApprovalCandidate,
    current_recipients: &[String],
    labels: RewrapReviewLabels<'_>,
    verify_online: &mut VerifyOnline,
    confirm_non_member: &mut ConfirmNonMember,
) -> Result<()>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String], &Path) -> Result<bool>,
{
    let reviewed = review_candidate_for_confirmation(
        candidate,
        InteractiveTrustReviewKind::NonMemberAcceptance,
        verify_online,
    )?;
    if confirm_non_member(
        &reviewed,
        labels.context,
        current_recipients,
        &requirement.file_path,
    )? {
        return Ok(());
    }
    Err(build_rewrap_rejection_error(
        &requirement.file_path,
        labels.approval_subject,
    ))
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
