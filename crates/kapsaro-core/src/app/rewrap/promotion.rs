// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Sorts incoming member public keys found during rewrap into auto-accepted
//! and manual-review buckets, then runs online verification on the latter.

use std::collections::BTreeSet;

use crate::app::trust::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};
use crate::feature::trust::judgment::{SelfTrustSet, TrustIdentity};
use crate::feature::trust::known_keys::{judge_known_key, KnownKeyJudgment};
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::trust_store::KnownKey;
use crate::{Error, Result};

use super::types::{
    IncomingPromotionCandidate, IncomingPromotionReviewPlan, IncomingVerificationCategory,
    IncomingVerificationReport,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionReviewFailure {
    pub member_handle: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionReviewPrompt {
    pub candidate: TrustApprovalCandidate,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromotionReviewView {
    pub failed_candidates: Vec<PromotionReviewFailure>,
    pub prompt_candidates: Vec<PromotionReviewPrompt>,
}

pub struct PromotionReviewSession {
    view: PromotionReviewView,
    auto_accepted_candidates: Vec<IncomingPromotionCandidate>,
    prompt_candidates: Vec<IncomingPromotionCandidate>,
}

struct PromotionReviewCandidates {
    auto_accepted: Vec<IncomingPromotionCandidate>,
    prompt: Vec<IncomingPromotionCandidate>,
}

impl PromotionReviewSession {
    pub fn view(&self) -> &PromotionReviewView {
        &self.view
    }

    pub fn into_accepted_candidates(
        self,
        accepted_member_handles: &[String],
    ) -> Vec<IncomingPromotionCandidate> {
        let accepted_ids = accepted_member_handles
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut accepted = self.auto_accepted_candidates;
        accepted.extend(
            self.prompt_candidates
                .into_iter()
                .filter(|candidate| accepted_ids.contains(&candidate.review.member_handle)),
        );
        accepted
    }
}

pub fn build_promotion_review_plan(
    report: &IncomingVerificationReport,
    known_keys: &[KnownKey],
    self_trust: &SelfTrustSet,
    is_interactive: bool,
) -> Result<IncomingPromotionReviewPlan> {
    let candidates = collect_promotion_review_candidates(report, known_keys, self_trust)?;
    enforce_interactive_promotion_review(&candidates.prompt, is_interactive)?;
    Ok(IncomingPromotionReviewPlan {
        failed_candidates: report.failed.clone(),
        auto_accepted_candidates: candidates.auto_accepted,
        prompt_candidates: candidates.prompt,
    })
}

fn collect_promotion_review_candidates(
    report: &IncomingVerificationReport,
    known_keys: &[KnownKey],
    self_trust: &SelfTrustSet,
) -> Result<PromotionReviewCandidates> {
    let mut auto_accepted = Vec::new();
    let mut prompt = Vec::new();
    for candidate in report
        .binding_configured
        .iter()
        .chain(report.not_configured.iter())
    {
        collect_promotion_review_candidate(
            candidate,
            known_keys,
            self_trust,
            &mut auto_accepted,
            &mut prompt,
        )?;
    }
    Ok(PromotionReviewCandidates {
        auto_accepted,
        prompt,
    })
}

fn collect_promotion_review_candidate(
    candidate: &IncomingPromotionCandidate,
    known_keys: &[KnownKey],
    self_trust: &SelfTrustSet,
    auto_accepted: &mut Vec<IncomingPromotionCandidate>,
    prompt: &mut Vec<IncomingPromotionCandidate>,
) -> Result<()> {
    let known_key_state = judge_known_key(
        known_keys,
        &candidate.review.kid,
        &candidate.review.member_handle,
    )?;
    if is_self_promotion_candidate(candidate, self_trust)? {
        auto_accepted.push(candidate.clone());
        return Ok(());
    }
    match known_key_state {
        KnownKeyJudgment::Existing => auto_accepted.push(candidate.clone()),
        KnownKeyJudgment::New => prompt.push(candidate.clone()),
    }
    Ok(())
}

fn enforce_interactive_promotion_review(
    prompt_candidates: &[IncomingPromotionCandidate],
    is_interactive: bool,
) -> Result<()> {
    if prompt_candidates.is_empty() || is_interactive {
        return Ok(());
    }
    Err(Error::build_verification_error(
        "V-TOFU".to_string(),
        "TOFU confirmation required for incoming members but stdin is not a terminal.".to_string(),
    ))
}

fn is_self_promotion_candidate(
    candidate: &IncomingPromotionCandidate,
    self_trust: &SelfTrustSet,
) -> Result<bool> {
    let Some(self_member_handle) = self_trust.member_handle() else {
        return Ok(false);
    };
    if candidate.review.member_handle != self_member_handle {
        return Ok(false);
    }

    let identity = TrustIdentity::from_public_key(&candidate.public_key)?;
    if self_trust.contains_identity(&identity)? {
        return Ok(true);
    }

    Err(Error::build_verification_error(
        "E_REWRAP_SELF_PROMOTION_MISMATCH".to_string(),
        format!(
            "Incoming self key '{}' ({}) did not match local keystore identity",
            candidate.review.member_handle, candidate.review.kid
        ),
    ))
}

pub fn build_promotion_review_session(
    review_plan: &IncomingPromotionReviewPlan,
) -> Result<PromotionReviewSession> {
    build_promotion_review_session_with_verifier(review_plan, |candidate| {
        verify_prompt_candidate_online(candidate)
    })
}

pub fn verify_prompt_candidate_online(
    candidate: &IncomingPromotionCandidate,
) -> Result<IncomingPromotionCandidate> {
    if !candidate.review.github_binding_configured {
        return Ok(candidate.clone());
    }

    let verified = crate::feature::verify::public_key::verify_public_key_for_verification_context(
        &candidate.public_key,
        crate::feature::verify::public_key::WORKSPACE_INCOMING_MEMBER_CONTEXT,
    )?;
    let service_candidate =
        crate::service::trust::KnownKeyReviewCandidate::from_verified_signing_public_key(
            &verified.verified_public_key,
        )?;
    let evidence = crate::service::online::GitHubOnlineVerifier::new()
        .verify_known_key_candidate(&service_candidate)?;
    let verified_github = VerifiedGithubIdentity::new(
        evidence.account().id(),
        evidence.account().login().to_string(),
        evidence.fingerprint().to_string(),
        evidence.matched_key_id(),
    );

    let mut reviewed = candidate.clone();
    reviewed.review.category = IncomingVerificationCategory::Verified;
    reviewed.review.message = "GitHub verification succeeded".to_string();
    reviewed.review.fingerprint = Some(evidence.fingerprint().to_string());
    reviewed.review.verified_github = Some(verified_github);
    reviewed.review.verified_service_evidence = Some(evidence);
    Ok(reviewed)
}

fn build_promotion_review_session_with_verifier<VerifyOnline>(
    review_plan: &IncomingPromotionReviewPlan,
    mut verify_online: VerifyOnline,
) -> Result<PromotionReviewSession>
where
    VerifyOnline: FnMut(&IncomingPromotionCandidate) -> Result<IncomingPromotionCandidate>,
{
    let mut failed_candidates = review_plan
        .failed_candidates
        .iter()
        .map(build_failed_candidate)
        .collect::<Vec<_>>();
    let mut prompt_candidates = Vec::new();
    let mut prompt_views = Vec::new();

    for candidate in &review_plan.prompt_candidates {
        let reviewed = if candidate.review.github_binding_configured {
            match verify_online(candidate) {
                Ok(reviewed) => reviewed,
                Err(error) => {
                    let failed = build_online_verification_failure(candidate, &error);
                    failed_candidates.push(build_failed_candidate(&failed));
                    continue;
                }
            }
        } else {
            candidate.clone()
        };
        if should_skip_prompt_candidate(&reviewed) {
            failed_candidates.push(build_failed_candidate(&reviewed));
            continue;
        }
        prompt_views.push(PromotionReviewPrompt {
            candidate: TrustApprovalCandidate::try_from(&reviewed)?,
        });
        prompt_candidates.push(reviewed);
    }

    Ok(PromotionReviewSession {
        view: PromotionReviewView {
            failed_candidates,
            prompt_candidates: prompt_views,
        },
        auto_accepted_candidates: review_plan.auto_accepted_candidates.clone(),
        prompt_candidates,
    })
}

fn build_online_verification_failure(
    candidate: &IncomingPromotionCandidate,
    error: &Error,
) -> IncomingPromotionCandidate {
    let mut failed = candidate.clone();
    failed.review.category = IncomingVerificationCategory::Failed;
    failed.review.message = error.format_user_message().to_string();
    failed.review.fingerprint = None;
    failed.review.verified_github = None;
    failed.review.verified_service_evidence = None;
    failed
}

fn should_skip_prompt_candidate(candidate: &IncomingPromotionCandidate) -> bool {
    (candidate.review.github_binding_configured
        && candidate.review.category != IncomingVerificationCategory::Verified)
        || candidate.review.category == IncomingVerificationCategory::Failed
}

fn build_failed_candidate(candidate: &IncomingPromotionCandidate) -> PromotionReviewFailure {
    PromotionReviewFailure {
        member_handle: candidate.review.member_handle.clone(),
        message: candidate.review.message.clone(),
    }
}

impl TryFrom<&IncomingPromotionCandidate> for TrustApprovalCandidate {
    type Error = Error;

    fn try_from(candidate: &IncomingPromotionCandidate) -> Result<Self> {
        let verified =
            crate::feature::verify::public_key::verify_public_key_for_verification_context(
                &candidate.public_key,
                crate::feature::verify::public_key::WORKSPACE_INCOMING_MEMBER_CONTEXT,
            )?;
        Ok(
            TrustApprovalCandidateBuilder::from_verified_signing_public_key(
                &verified.verified_public_key,
            )?
            .with_online_verification_context(
                candidate.review.github_binding_configured,
                Some(candidate.review.message.clone()),
            )
            .with_optional_verified_service_evidence(
                candidate.review.verified_service_evidence.clone(),
            )
            .build(),
        )
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_rewrap_promotion_test.rs"]
mod tests;
