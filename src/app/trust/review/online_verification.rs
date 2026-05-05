// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::trust::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};
use crate::feature::member::verification::verify_member_public_keys;
use crate::support::runtime::block_on_result;
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
    if !candidate.github_binding_configured || candidate.verified_github.is_some() {
        return Ok(candidate.clone());
    }

    let reviewed = verify_online(candidate)?;
    if reviewed.verified_github.is_some() {
        return Ok(reviewed);
    }

    if matches!(review_kind, InteractiveTrustReviewKind::NonMemberAcceptance) {
        return Ok(reviewed);
    }

    Err(build_online_verification_required_error(&reviewed))
}

pub(super) fn verify_trust_candidate_online(
    candidate: &TrustApprovalCandidate,
    verbose: bool,
) -> Result<TrustApprovalCandidate> {
    if !candidate.github_binding_configured || candidate.verified_github.is_some() {
        return Ok(candidate.clone());
    }

    let public_key = candidate.public_key.as_ref().ok_or_else(|| Error::Verify {
        rule: "E_TRUST_REVIEW_SOURCE_MISSING".to_string(),
        message: format!(
            "Missing public key required for online verification of '{}' ({})",
            candidate.member_handle, candidate.kid
        ),
    })?;
    let results = block_on_result(verify_member_public_keys(
        std::slice::from_ref(public_key),
        verbose,
    ))?;
    let result = results.into_iter().next().ok_or_else(|| Error::Verify {
        rule: "E_TRUST_ONLINE_VERIFY_MISSING".to_string(),
        message: format!(
            "Online verification produced no result for '{}' ({})",
            candidate.member_handle, candidate.kid
        ),
    })?;

    if result.member_handle != candidate.member_handle.as_str() {
        return Err(Error::Verify {
            rule: "E_TRUST_ONLINE_VERIFY_MISMATCH".to_string(),
            message: format!(
                "Online verification result member_handle '{}' did not match candidate '{}'",
                result.member_handle, candidate.member_handle
            ),
        });
    }

    Ok(apply_online_verification_result(candidate, result))
}

fn apply_online_verification_result(
    candidate: &TrustApprovalCandidate,
    result: crate::io::verify_online::VerificationResult,
) -> TrustApprovalCandidate {
    TrustApprovalCandidateBuilder::new(candidate.member_handle.as_str(), candidate.kid.as_str())
        .with_fingerprint(candidate.fingerprint.clone())
        .with_attestor_pub(candidate.attestor_pub.clone())
        .with_verified_github(candidate.verified_github.clone())
        .with_github_binding_configured(candidate.github_binding_configured)
        .with_public_key(candidate.public_key.clone())
        .with_online_verification_context(
            candidate.online_verification_attempted,
            candidate.online_verification_message.clone(),
        )
        .with_verification_result(&result)
        .build()
}

fn build_online_verification_required_error(candidate: &TrustApprovalCandidate) -> Error {
    Error::Verify {
        rule: "E_TRUST_ONLINE_VERIFY_REQUIRED".to_string(),
        message: format!(
            "Online verification required for trust approval of '{}' ({}): {}",
            candidate.member_handle,
            candidate.kid,
            candidate
                .online_verification_message
                .as_deref()
                .unwrap_or("online verification did not succeed")
        ),
    }
}
