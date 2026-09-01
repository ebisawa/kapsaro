// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Runs GitHub-binding online verification on a single trust candidate.
//! Skips candidates with no binding configured or already verified, and
//! turns an unresolved result into an error unless non-member acceptance allows it.

use crate::app::trust::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};
use crate::service::online::GitHubOnlineVerifier;
use crate::{Error, Result};

#[derive(Clone, Copy)]
pub(super) enum InteractiveTrustReviewKind {
    KnownKeyApproval,
    NonMemberAcceptance,
}

pub(super) fn review_candidate_for_confirmation<VerifyOnline>(
    candidate: &TrustApprovalCandidate,
    review_kind: InteractiveTrustReviewKind,
    verify_online: &mut VerifyOnline,
) -> Result<TrustApprovalCandidate>
where
    VerifyOnline: FnMut(&TrustApprovalCandidate) -> Result<TrustApprovalCandidate>,
{
    if !candidate.github_binding_configured() || candidate.is_github_verified() {
        return Ok(candidate.clone());
    }

    let reviewed = match verify_online(candidate) {
        Ok(reviewed) => reviewed,
        Err(error) if matches!(review_kind, InteractiveTrustReviewKind::NonMemberAcceptance) => {
            TrustApprovalCandidateBuilder::from_known_key_candidate(candidate.service_candidate())
                .with_online_verification_context(
                    true,
                    Some(error.format_user_message().to_string()),
                )
                .build()
        }
        Err(error) => return Err(error),
    };
    if reviewed.is_github_verified() {
        return Ok(reviewed);
    }

    if matches!(review_kind, InteractiveTrustReviewKind::NonMemberAcceptance) {
        return Ok(reviewed);
    }

    Err(build_online_verification_required_error(&reviewed))
}

pub(super) fn verify_trust_candidate_online(
    candidate: &TrustApprovalCandidate,
) -> Result<TrustApprovalCandidate> {
    if !candidate.github_binding_configured() || candidate.is_github_verified() {
        return Ok(candidate.clone());
    }

    let service_candidate = candidate.service_candidate();
    let evidence = GitHubOnlineVerifier::new().verify_known_key_candidate(service_candidate)?;
    Ok(
        TrustApprovalCandidateBuilder::from_known_key_candidate(service_candidate)
            .with_online_verification_context(
                true,
                Some("GitHub verification succeeded".to_string()),
            )
            .with_verified_service_evidence(evidence)
            .build(),
    )
}

fn build_online_verification_required_error(candidate: &TrustApprovalCandidate) -> Error {
    Error::build_verification_error(
        "E_TRUST_ONLINE_VERIFY_REQUIRED".to_string(),
        format!(
            "Online verification required for trust approval of '{}' ({}): {}",
            candidate.member_handle(),
            candidate.kid(),
            candidate
                .online_verification_message()
                .unwrap_or("online verification did not succeed")
        ),
    )
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/app_trust_review_online_verification_test.rs"]
mod tests;
