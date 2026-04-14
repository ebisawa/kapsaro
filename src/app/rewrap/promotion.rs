// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use crate::app::trust::TrustApprovalCandidate;
use crate::feature::member::verification::verify_member_public_keys;
use crate::feature::trust::judgment::{SelfTrustSet, TrustIdentity};
use crate::feature::trust::known_keys::{assess_known_key, KnownKeyAssessment};
use crate::io::verify_online::VerificationStatus;
use crate::model::identity::{Kid, MemberId};
use crate::model::trust_store::KnownKey;
use crate::support::runtime::block_on_result;
use crate::{Error, Result};

use super::types::{
    IncomingPromotionCandidate, IncomingPromotionReviewPlan, IncomingVerificationCategory,
    IncomingVerificationReport,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromotionReviewFailure {
    pub(crate) member_id: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromotionReviewPrompt {
    pub(crate) candidate: TrustApprovalCandidate,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PromotionReviewView {
    pub(crate) failed_candidates: Vec<PromotionReviewFailure>,
    pub(crate) prompt_candidates: Vec<PromotionReviewPrompt>,
}

pub(crate) struct PromotionReviewSession {
    view: PromotionReviewView,
    auto_accepted_candidates: Vec<IncomingPromotionCandidate>,
    prompt_candidates: Vec<IncomingPromotionCandidate>,
}

impl PromotionReviewSession {
    pub(crate) fn view(&self) -> &PromotionReviewView {
        &self.view
    }

    pub(crate) fn into_accepted_candidates(
        self,
        accepted_member_ids: &[String],
    ) -> Vec<IncomingPromotionCandidate> {
        let accepted_ids = accepted_member_ids.iter().cloned().collect::<BTreeSet<_>>();
        let mut accepted = self.auto_accepted_candidates;
        accepted.extend(
            self.prompt_candidates
                .into_iter()
                .filter(|candidate| accepted_ids.contains(&candidate.review.member_id)),
        );
        accepted
    }
}

pub(crate) fn build_promotion_review_plan(
    report: &IncomingVerificationReport,
    known_keys: &[KnownKey],
    self_trust: &SelfTrustSet,
    is_interactive: bool,
) -> Result<IncomingPromotionReviewPlan> {
    let mut auto_accepted_candidates = Vec::new();
    let mut prompt_candidates = Vec::new();
    for candidate in report
        .binding_configured
        .iter()
        .chain(report.not_configured.iter())
    {
        let known_key_state = assess_known_key(
            known_keys,
            &candidate.review.kid,
            &candidate.review.member_id,
        )?;
        if is_self_promotion_candidate(candidate, self_trust)? {
            auto_accepted_candidates.push(candidate.clone());
            continue;
        }
        match known_key_state {
            KnownKeyAssessment::Existing => auto_accepted_candidates.push(candidate.clone()),
            KnownKeyAssessment::New => prompt_candidates.push(candidate.clone()),
        }
    }

    if prompt_candidates.is_empty() {
        return Ok(IncomingPromotionReviewPlan {
            failed_candidates: report.failed.clone(),
            auto_accepted_candidates,
            prompt_candidates,
        });
    }

    if !is_interactive {
        return Err(Error::Verify {
            rule: "V-TOFU".to_string(),
            message: "TOFU confirmation required for incoming members but stdin is not a terminal."
                .to_string(),
        });
    }

    Ok(IncomingPromotionReviewPlan {
        failed_candidates: report.failed.clone(),
        auto_accepted_candidates,
        prompt_candidates,
    })
}

fn is_self_promotion_candidate(
    candidate: &IncomingPromotionCandidate,
    self_trust: &SelfTrustSet,
) -> Result<bool> {
    let Some(self_member_id) = self_trust.member_id() else {
        return Ok(false);
    };
    if candidate.review.member_id != self_member_id {
        return Ok(false);
    }

    let identity = TrustIdentity::from_public_key(&candidate.public_key)?;
    if self_trust.contains_identity(&identity)? {
        return Ok(true);
    }

    Err(Error::Verify {
        rule: "E_REWRAP_SELF_PROMOTION_MISMATCH".to_string(),
        message: format!(
            "Incoming self key '{}' ({}) did not match local keystore identity",
            candidate.review.member_id, candidate.review.kid
        ),
    })
}

pub(crate) fn build_promotion_review_session(
    review_plan: &IncomingPromotionReviewPlan,
    verbose: bool,
) -> Result<PromotionReviewSession> {
    build_promotion_review_session_with_verifier(review_plan, |candidate| {
        verify_prompt_candidate_online(candidate, verbose)
    })
}

pub(crate) fn verify_prompt_candidate_online(
    candidate: &IncomingPromotionCandidate,
    verbose: bool,
) -> Result<IncomingPromotionCandidate> {
    if !candidate.review.github_binding_configured {
        return Ok(candidate.clone());
    }

    let results = block_on_result(verify_member_public_keys(
        std::slice::from_ref(&candidate.public_key),
        verbose,
    ))?;
    let result = results.into_iter().next().ok_or_else(|| Error::Verify {
        rule: "E_REWRAP_MISSING_VERIFICATION_RESULT".to_string(),
        message: format!(
            "Online verification produced no result for incoming member '{}'",
            candidate.review.member_id
        ),
    })?;

    if result.member_id != candidate.review.member_id {
        return Err(Error::Verify {
            rule: "E_REWRAP_VERIFICATION_RESULT_MISMATCH".to_string(),
            message: format!(
                "Online verification result member_id '{}' did not match candidate '{}'",
                result.member_id, candidate.review.member_id
            ),
        });
    }

    let category = match result.status {
        VerificationStatus::Verified => IncomingVerificationCategory::Verified,
        VerificationStatus::Failed => IncomingVerificationCategory::Failed,
        VerificationStatus::NotConfigured => IncomingVerificationCategory::NotConfigured,
    };

    let mut reviewed = candidate.clone();
    reviewed.review.category = category;
    reviewed.review.message = result.message;
    reviewed.review.fingerprint = result.fingerprint;
    reviewed.review.verified_github = result.verified_github;
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
            verify_online(candidate)?
        } else {
            candidate.clone()
        };
        if should_skip_prompt_candidate(&reviewed) {
            failed_candidates.push(build_failed_candidate(&reviewed));
            continue;
        }
        prompt_views.push(PromotionReviewPrompt {
            candidate: (&reviewed).into(),
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

fn should_skip_prompt_candidate(candidate: &IncomingPromotionCandidate) -> bool {
    (candidate.review.github_binding_configured
        && candidate.review.category != IncomingVerificationCategory::Verified)
        || candidate.review.category == IncomingVerificationCategory::Failed
}

fn build_failed_candidate(candidate: &IncomingPromotionCandidate) -> PromotionReviewFailure {
    PromotionReviewFailure {
        member_id: candidate.review.member_id.clone(),
        message: candidate.review.message.clone(),
    }
}

impl From<&IncomingPromotionCandidate> for TrustApprovalCandidate {
    fn from(candidate: &IncomingPromotionCandidate) -> Self {
        TrustApprovalCandidate {
            member_id: MemberId::try_from(candidate.review.member_id.clone())
                .expect("incoming member_id must be valid"),
            kid: Kid::try_from(candidate.review.kid.clone()).expect("incoming kid must be valid"),
            fingerprint: candidate.review.fingerprint.clone(),
            github_id: candidate
                .review
                .verified_github
                .as_ref()
                .map(|account| account.id),
            github_login: candidate
                .review
                .verified_github
                .as_ref()
                .map(|account| account.login.clone()),
            attestor_pub: candidate.review.attestor_pub.clone(),
            verified_github: candidate.review.verified_github.clone(),
            github_binding_configured: candidate.review.github_binding_configured,
            online_verification_attempted: candidate.review.github_binding_configured,
            online_verification_message: Some(candidate.review.message.clone()),
            public_key: Some(candidate.public_key.clone()),
            requires_out_of_band_verification: true,
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/app_rewrap_promotion_test.rs"]
mod tests;
