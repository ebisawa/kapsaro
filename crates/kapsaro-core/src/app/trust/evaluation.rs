// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust evaluation helpers built on immutable command snapshots.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::policy::{ReadTrustPolicy, TrustPolicy};
use crate::app::trust::snapshot::{load_read_trust_context, TrustContext};
use crate::app::trust::{
    ArtifactRecipientTrustOutcome, RecipientTrustOutcome, SignerTrustOutcome,
    TrustApprovalCandidateBuilder,
};
use crate::feature::context::crypto::LocalKeyIdentity;
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::model::verification::SignatureVerificationProof;
use crate::service::key::KeyContext;
use crate::service::trust::{
    KnownKeyReview, ReadTrustReview, TrustDecision, TrustPolicyEvaluator, TrustReviewKind,
    TrustReviewRequest,
};
use crate::support::warning::push_unique_warning;
use crate::Result;

pub struct ReadArtifactTrustPlan {
    pub signer_outcome: SignerTrustOutcome,
    pub recipient_outcome: RecipientTrustOutcome,
    pub known_key_review: KnownKeyReview,
    pub warnings: Vec<String>,
}

pub(crate) fn build_read_artifact_trust_plan(
    review: ReadTrustReview,
    proof: &SignatureVerificationProof,
    known_key_review: KnownKeyReview,
    is_interactive: bool,
    mut warnings: Vec<String>,
) -> Result<ReadArtifactTrustPlan> {
    let signer_kid = proof
        .signer_public_key
        .as_ref()
        .map(|key| key.protected.kid.as_str());
    let signer_outcome = signer_outcome_from_review(&review, signer_kid, is_interactive)?;
    for kid in review.unresolved_recipient_kids() {
        push_unique_warning(&mut warnings, build_unresolved_recipient_warning(kid));
    }
    let requests = review.into_recipient_requests()?;
    let recipient_outcome = recipient_outcome_from_requests(&requests, signer_kid, is_interactive)?;
    Ok(ReadArtifactTrustPlan {
        signer_outcome,
        recipient_outcome,
        known_key_review,
        warnings,
    })
}

fn build_unresolved_recipient_warning(kid: &crate::model::identity::Kid) -> String {
    format!(
        "Recipient kid is not active.\n\
         Kid: {}\n\
         Details: This may be historical metadata from a stale recipient.\n\
         Action: Run kapsaro rewrap to synchronize current recipients.",
        kid
    )
}

pub(crate) fn known_key_review(trust_ctx: &TrustContext) -> KnownKeyReview {
    if trust_ctx.strict_key_checking.is_disabled() {
        KnownKeyReview::Skipped
    } else {
        KnownKeyReview::Required
    }
}

pub(crate) fn resolve_read_trust_context_for_policy<P>(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
) -> Result<crate::app::trust::snapshot::ReadTrustContextLoadResult>
where
    P: ReadTrustPolicy,
{
    load_read_trust_context(
        options,
        execution,
        &format!("{} trust evaluation", P::CAPABILITY.label()),
    )
}

fn signer_outcome_from_review(
    review: &ReadTrustReview,
    signer_kid: Option<&str>,
    is_interactive: bool,
) -> Result<SignerTrustOutcome> {
    if let Some(non_member) = review.non_member_signer() {
        let candidate =
            TrustApprovalCandidateBuilder::from_known_key_candidate(non_member.candidate()).build();
        enforce_interactive_review(is_interactive, non_member_review_error(&candidate))?;
        return Ok(SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate,
            current_recipients: non_member
                .recipient_handles()
                .iter()
                .map(ToString::to_string)
                .collect(),
        });
    }
    let signer_request = review.requests().iter().find(|request| {
        request.kid().map(|kid| kid.as_str()) == signer_kid
            && request.kind() == TrustReviewKind::KnownKey
    });
    let Some(request) = signer_request else {
        return Ok(SignerTrustOutcome::Accepted);
    };
    let candidate = review_candidate(request)?;
    enforce_interactive_review(is_interactive, unknown_signer_review_error(&candidate))?;
    Ok(SignerTrustOutcome::NeedsKnownKeyApproval(candidate))
}

fn recipient_outcome_from_requests(
    requests: &[TrustReviewRequest],
    signer_kid: Option<&str>,
    is_interactive: bool,
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
        enforce_interactive_review(
            is_interactive,
            unknown_recipient_candidate_error(&candidates),
        )?;
        Ok(RecipientTrustOutcome::NeedsManualApproval(candidates))
    }
}

pub(crate) fn recipient_outcome_from_decision<T>(
    decision: TrustDecision<T>,
    is_interactive: bool,
) -> Result<RecipientTrustOutcome> {
    match decision {
        TrustDecision::Trusted(_) => Ok(RecipientTrustOutcome::Accepted),
        TrustDecision::ReviewRequired(requests) if is_interactive => {
            recipient_outcome_from_requests(&requests, None, is_interactive)
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
    candidates: &[crate::app::trust::TrustApprovalCandidate],
) -> crate::Error {
    let recipients = candidates
        .iter()
        .map(|candidate| format!("'{}' ({})", candidate.kid(), candidate.member_handle()))
        .collect::<Vec<_>>();
    crate::Error::build_verification_error(
        "E_TRUST_RECIPIENT_UNKNOWN".to_string(),
        format!(
            "Unknown recipient kid requires approval.\nRecipients: {}\nAction: Run kapsaro member verify --approve first.",
            recipients.join(", ")
        ),
    )
}

fn unknown_signer_review_error(
    candidate: &crate::app::trust::TrustApprovalCandidate,
) -> crate::Error {
    crate::Error::build_verification_error(
        "E_TRUST_UNKNOWN_SIGNER".to_string(),
        format!(
            "Unknown signer kid '{}' (member: {}) in non-interactive mode",
            candidate.kid(),
            candidate.member_handle()
        ),
    )
}

fn non_member_review_error(candidate: &crate::app::trust::TrustApprovalCandidate) -> crate::Error {
    crate::Error::build_verification_error(
        "E_TRUST_NON_MEMBER".to_string(),
        format!(
            "Signer is not in active members.\nsigner: {}\nkid: {}\nNon-member acceptance requires an interactive terminal.",
            candidate.member_handle(),
            candidate.kid()
        ),
    )
}

fn enforce_interactive_review(is_interactive: bool, error: crate::Error) -> Result<()> {
    if is_interactive {
        Ok(())
    } else {
        Err(error)
    }
}

fn review_candidate(
    request: &TrustReviewRequest,
) -> Result<crate::app::trust::TrustApprovalCandidate> {
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
        if suppress_local_signer_expiry && is_signer_key_expiry_warning(warning) {
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
    is_interactive: bool,
) -> Result<SignerTrustOutcome> {
    match decision {
        TrustDecision::Trusted(_) => Ok(SignerTrustOutcome::Accepted),
        TrustDecision::ReviewRequired(requests) => {
            signer_outcome_from_requests(requests, signer_kid, is_interactive)
        }
    }
}

fn signer_outcome_from_requests(
    requests: &[TrustReviewRequest],
    signer_kid: Option<&str>,
    is_interactive: bool,
) -> Result<SignerTrustOutcome> {
    let request = requests.iter().find(|request| {
        request.kind() == TrustReviewKind::KnownKey
            && request.kid().map(|kid| kid.as_str()) == signer_kid
    });
    let Some(candidate) = request.map(review_candidate).transpose()? else {
        return Ok(SignerTrustOutcome::Accepted);
    };
    enforce_interactive_review(is_interactive, unknown_signer_review_error(&candidate))?;
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
    if !trust_ctx.is_interactive {
        let (rule, message) = match request.kind() {
            TrustReviewKind::ChangedRecipientSet => (
                "E_RECIPIENT_SET_CHANGED",
                "This secret's member set changed since local review.\nAction: Run the command interactively to review it first.",
            ),
            _ => (
                "E_RECIPIENT_TRUST_MISSING",
                "This secret's member set has not been reviewed locally.\nAction: Run the command interactively to review it first.",
            ),
        };
        return Err(crate::Error::build_verification_error(
            rule.to_string(),
            message.to_string(),
        ));
    }
    let approved = (request.kind() == TrustReviewKind::ChangedRecipientSet)
        .then(|| {
            trust_ctx
                .recipient_sets
                .iter()
                .find(|record| record.sid == current.sid().to_string())
                .cloned()
        })
        .flatten();
    Ok(ArtifactRecipientTrustOutcome::NeedsManualApproval(
        Box::new(crate::app::trust::ArtifactRecipientSetReview::new(
            current.clone(),
            approved,
        )),
    ))
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

fn is_signer_key_expiry_warning(warning: &str) -> bool {
    warning.starts_with("Artifact signing key expires in ")
        || warning.starts_with("Artifact signing key has expired.")
        || warning.starts_with("PublicKey for ")
}

pub fn enforce_policy_strict_key_checking<P>(
    strict_key_checking: crate::config::types::StrictKeyCheckingResolution,
) -> Result<()>
where
    P: TrustPolicy,
{
    if !P::CAPABILITY.allows_strict_key_checking_no() && strict_key_checking.is_disabled() {
        return Err(crate::Error::build_invalid_operation_error(format!(
            "KAPSARO_STRICT_KEY_CHECKING=no is not allowed for {}",
            P::CAPABILITY.label()
        )));
    }
    Ok(())
}
