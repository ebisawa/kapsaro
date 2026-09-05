// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust evaluation helpers built on immutable command snapshots.

use crate::feature::context::crypto::LocalKeyIdentity;
use crate::feature::context::expiry::is_key_expiry_warning;
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::model::verification::SignatureVerificationProof;
use crate::service::key::KeyContext;
use crate::service::trust::snapshot::TrustContext;
use crate::service::trust::{
    ArtifactRecipientTrustOutcome, RecipientTrustOutcome, SignerTrustOutcome,
    TrustApprovalCandidateBuilder,
};
use crate::service::trust::{
    TrustDecision, TrustPolicyEvaluator, TrustReviewKind, TrustReviewRequest,
};
use crate::support::warning::push_unique_warning;
use crate::Result;

fn recipient_outcome_from_requests(
    requests: &[TrustReviewRequest],
    signer_kid: Option<&str>,
    review_available: bool,
) -> Result<RecipientTrustOutcome> {
    let candidates = requests
        .iter()
        .filter(|request| {
            request.kind() == TrustReviewKind::KnownKey
                && request.kid().map(|kid| kid.as_str()) != signer_kid
        })
        .map(review_candidate)
        .collect::<Result<Vec<_>>>()?;
    if candidates.is_empty() {
        Ok(RecipientTrustOutcome::Accepted)
    } else {
        require_review_available(
            review_available,
            unknown_recipient_candidate_error(&candidates),
        )?;
        Ok(RecipientTrustOutcome::NeedsManualApproval(candidates))
    }
}

pub(crate) fn recipient_outcome_from_decision<T>(
    decision: TrustDecision<T>,
    review_available: bool,
) -> Result<RecipientTrustOutcome> {
    match decision {
        TrustDecision::Trusted(_) => Ok(RecipientTrustOutcome::Accepted),
        TrustDecision::ReviewRequired(requests) if review_available => {
            recipient_outcome_from_requests(&requests, None, review_available)
        }
        TrustDecision::ReviewRequired(requests) => Err(unknown_recipient_review_error(&requests)),
    }
}

fn unknown_recipient_review_error(requests: &[TrustReviewRequest]) -> crate::Error {
    let candidates = requests
        .iter()
        .filter_map(|request| review_candidate(request).ok())
        .collect::<Vec<_>>();
    unknown_recipient_candidate_error(&candidates)
}

fn unknown_recipient_candidate_error(
    candidates: &[crate::service::trust::TrustApprovalCandidate],
) -> crate::Error {
    let recipients = candidates
        .iter()
        .map(|candidate| format!("'{}' ({})", candidate.kid(), candidate.member_handle()))
        .collect::<Vec<_>>();
    crate::Error::build_verification_error(
        "E_TRUST_REJECTED".to_string(),
        format!(
            "Unknown recipient kid requires approval.\nRecipients: {}",
            recipients.join(", ")
        ),
    )
}

fn unknown_signer_review_error(
    candidate: &crate::service::trust::TrustApprovalCandidate,
) -> crate::Error {
    crate::Error::build_verification_error(
        "E_TRUST_REJECTED".to_string(),
        format!(
            "Unknown signer kid '{}' (member: {}) requires review",
            candidate.kid(),
            candidate.member_handle()
        ),
    )
}

fn require_review_available(review_available: bool, error: crate::Error) -> Result<()> {
    if review_available {
        Ok(())
    } else {
        Err(error)
    }
}

fn review_candidate(
    request: &TrustReviewRequest,
) -> Result<crate::service::trust::TrustApprovalCandidate> {
    let candidate = request.known_key_candidate().ok_or_else(|| {
        crate::Error::build_invalid_operation_error(
            "Known-key review request is missing its verified candidate".to_string(),
        )
    })?;
    Ok(TrustApprovalCandidateBuilder::from_known_key_candidate(candidate).build())
}

pub(crate) fn push_signature_verification_warnings(
    warnings: &mut Vec<String>,
    proof: &SignatureVerificationProof,
    local_key_identity: Option<&LocalKeyIdentity>,
) -> Result<()> {
    let suppress_local_signer_expiry = matches_local_signer_identity(proof, local_key_identity)?;
    for warning in &proof.warnings {
        if suppress_local_signer_expiry && is_key_expiry_warning(warning) {
            continue;
        }
        push_unique_warning(warnings, warning.clone());
    }
    Ok(())
}

pub fn evaluate_output_recipient_set_trust(
    evaluator: &TrustPolicyEvaluator,
    key_ctx: &KeyContext,
    trust_ctx: &TrustContext,
    recipient_set: &ArtifactRecipientSet,
) -> Result<ArtifactRecipientTrustOutcome> {
    let decision = evaluator.preflight_recipient_set(recipient_set, key_ctx)?;
    artifact_recipient_outcome_from_decision(decision, trust_ctx, recipient_set)
}

pub(crate) fn signer_outcome_from_decision<T>(
    decision: &TrustDecision<T>,
    signer_kid: Option<&str>,
    review_available: bool,
) -> Result<SignerTrustOutcome> {
    match decision {
        TrustDecision::Trusted(_) => Ok(SignerTrustOutcome::Accepted),
        TrustDecision::ReviewRequired(requests) => {
            signer_outcome_from_requests(requests, signer_kid, review_available)
        }
    }
}

fn signer_outcome_from_requests(
    requests: &[TrustReviewRequest],
    signer_kid: Option<&str>,
    review_available: bool,
) -> Result<SignerTrustOutcome> {
    let request = requests.iter().find(|request| {
        request.kind() == TrustReviewKind::KnownKey
            && request.kid().map(|kid| kid.as_str()) == signer_kid
    });
    let Some(candidate) = request.map(review_candidate).transpose()? else {
        return Ok(SignerTrustOutcome::Accepted);
    };
    require_review_available(review_available, unknown_signer_review_error(&candidate))?;
    Ok(SignerTrustOutcome::NeedsKnownKeyApproval(candidate))
}

pub(crate) fn artifact_recipient_outcome_from_decision<T>(
    decision: TrustDecision<T>,
    trust_ctx: &TrustContext,
    current: &ArtifactRecipientSet,
) -> Result<ArtifactRecipientTrustOutcome> {
    let TrustDecision::ReviewRequired(requests) = decision else {
        return Ok(ArtifactRecipientTrustOutcome::Accepted);
    };
    let Some(request) = requests.iter().find(|request| {
        matches!(
            request.kind(),
            TrustReviewKind::RecipientSet | TrustReviewKind::ChangedRecipientSet
        )
    }) else {
        return Ok(ArtifactRecipientTrustOutcome::Accepted);
    };
    require_review_available(
        trust_ctx.review_available,
        unreviewed_recipient_set_error(request.kind()),
    )?;
    let approved = find_approved_recipient_set(trust_ctx, current, request.kind());
    Ok(ArtifactRecipientTrustOutcome::NeedsManualApproval(
        Box::new(crate::service::trust::ArtifactRecipientSetReview::new(
            current.clone(),
            approved,
        )),
    ))
}

/// State that a recipient set needs approval no run without review can give.
fn unreviewed_recipient_set_error(kind: TrustReviewKind) -> crate::Error {
    let (rule, message) = match kind {
        TrustReviewKind::ChangedRecipientSet => (
            "E_RECIPIENT_SET_CHANGED",
            "This secret's member set changed since local review and requires approval.",
        ),
        _ => (
            "E_RECIPIENT_TRUST_MISSING",
            "This secret's member set has not been reviewed locally and requires approval.",
        ),
    };
    crate::Error::build_verification_error(rule.to_string(), message.to_string())
}

/// Return the set the last approval stored, which only a changed set has.
fn find_approved_recipient_set(
    trust_ctx: &TrustContext,
    current: &ArtifactRecipientSet,
    kind: TrustReviewKind,
) -> Option<crate::model::trust_store::RecipientSetRecord> {
    if kind != TrustReviewKind::ChangedRecipientSet {
        return None;
    }
    trust_ctx
        .recipient_sets
        .iter()
        .find(|record| record.sid == current.sid().to_string())
        .cloned()
}

fn matches_local_signer_identity(
    proof: &SignatureVerificationProof,
    local_key_identity: Option<&LocalKeyIdentity>,
) -> Result<bool> {
    let (Some(identity), Some(signer_public_key)) = (local_key_identity, &proof.signer_public_key)
    else {
        return Ok(false);
    };
    identity.matches_public_key(signer_public_key)
}

pub fn enforce_write_strict_key_checking(
    strict_key_checking: crate::config::types::StrictKeyCheckingResolution,
) -> Result<()> {
    if strict_key_checking.is_disabled() {
        return Err(crate::Error::build_invalid_operation_error(
            "Strict key checking cannot be disabled for write operations".to_string(),
        ));
    }
    Ok(())
}
