// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Presents a service-verified trust candidate to interactive callers.
//! Identity is always projected from the retained service capability.

use crate::io::verify_online::VerificationResult;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::VerifiedSigningPublicKey;
use crate::service::online::VerifiedGitHubEvidence;
use crate::service::trust::KnownKeyReviewCandidate;

/// Review material for a manual trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustApprovalCandidate {
    service_candidate: KnownKeyReviewCandidate,
    verified_service_evidence: Option<VerifiedGitHubEvidence>,
    online_verification_attempted: bool,
    online_verification_message: Option<String>,
    pub requires_out_of_band_verification: bool,
}

impl TrustApprovalCandidate {
    #[cfg(any(test, feature = "cli-test-support"))]
    pub fn for_test(member_handle: &str, kid: &str, github_binding_configured: bool) -> Self {
        TrustApprovalCandidateBuilder::from_known_key_candidate(
            &KnownKeyReviewCandidate::for_test_with_github_binding(
                member_handle,
                kid,
                "ssh-ed25519 AAAA test",
                github_binding_configured,
            ),
        )
        .build()
    }

    #[cfg(any(test, feature = "cli-test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn for_test_review(
        member_handle: &str,
        kid: &str,
        fingerprint: Option<String>,
        github_binding_configured: bool,
        verified_github: Option<(u64, String, String, i64)>,
        online_verification_attempted: bool,
        online_verification_message: Option<String>,
        requires_out_of_band_verification: bool,
    ) -> Self {
        let github_account_id = verified_github
            .as_ref()
            .map(|(id, ..)| *id)
            .or_else(|| github_binding_configured.then_some(42));
        let service_candidate = KnownKeyReviewCandidate::for_test_with_github_account_id(
            member_handle,
            kid,
            "ssh-ed25519 AAAA test",
            github_account_id,
            fingerprint,
        );
        let evidence = verified_github.map(|(id, login, fingerprint, matched_key_id)| {
            VerifiedGitHubEvidence::for_test(
                &service_candidate,
                id,
                login,
                fingerprint,
                matched_key_id,
            )
        });
        let mut candidate =
            TrustApprovalCandidateBuilder::from_known_key_candidate(&service_candidate)
                .with_optional_verified_service_evidence(evidence)
                .with_online_verification_context(
                    online_verification_attempted,
                    online_verification_message,
                )
                .build();
        candidate.requires_out_of_band_verification = requires_out_of_band_verification;
        candidate
    }

    pub fn member_handle(&self) -> &MemberHandle {
        self.service_candidate.subject_handle()
    }

    pub fn kid(&self) -> &Kid {
        self.service_candidate.kid()
    }

    pub fn fingerprint(&self) -> Option<&str> {
        self.verified_service_evidence
            .as_ref()
            .map(VerifiedGitHubEvidence::fingerprint)
            .or_else(|| self.service_candidate.fingerprint())
    }

    pub fn github_id(&self) -> Option<u64> {
        self.verified_service_evidence
            .as_ref()
            .map(|evidence| evidence.account().id())
    }

    pub fn github_login(&self) -> Option<&str> {
        self.verified_service_evidence
            .as_ref()
            .map(|evidence| evidence.account().login())
    }

    pub fn attestor_pub(&self) -> &str {
        self.service_candidate.ssh_attestor_public_key()
    }

    pub fn github_binding_configured(&self) -> bool {
        self.service_candidate.has_github_binding()
    }

    pub fn is_github_verified(&self) -> bool {
        self.verified_service_evidence.is_some()
    }

    pub fn online_verification_attempted(&self) -> bool {
        self.online_verification_attempted
    }

    pub fn online_verification_message(&self) -> Option<&str> {
        self.online_verification_message.as_deref()
    }

    pub(crate) fn service_candidate(&self) -> &KnownKeyReviewCandidate {
        &self.service_candidate
    }

    pub(crate) fn verified_service_evidence(&self) -> Option<&VerifiedGitHubEvidence> {
        self.verified_service_evidence.as_ref()
    }
}

pub struct TrustApprovalCandidateBuilder {
    candidate: TrustApprovalCandidate,
}

impl TrustApprovalCandidateBuilder {
    pub(crate) fn from_verified_signing_public_key(
        public_key: &VerifiedSigningPublicKey,
    ) -> Result<Self, crate::Error> {
        let candidate = KnownKeyReviewCandidate::from_verified_signing_public_key(public_key)?;
        Ok(Self::from_known_key_candidate(&candidate))
    }

    pub(crate) fn from_known_key_candidate(candidate: &KnownKeyReviewCandidate) -> Self {
        Self {
            candidate: TrustApprovalCandidate {
                service_candidate: candidate.clone(),
                verified_service_evidence: None,
                online_verification_attempted: false,
                online_verification_message: None,
                requires_out_of_band_verification: true,
            },
        }
    }

    pub(crate) fn with_verified_service_evidence(
        mut self,
        evidence: VerifiedGitHubEvidence,
    ) -> Self {
        self.candidate.verified_service_evidence = Some(evidence);
        self
    }

    pub(crate) fn with_optional_verified_service_evidence(
        self,
        evidence: Option<VerifiedGitHubEvidence>,
    ) -> Self {
        match evidence {
            Some(evidence) => self.with_verified_service_evidence(evidence),
            None => self,
        }
    }

    pub fn with_verification_result(mut self, result: &VerificationResult) -> Self {
        self.candidate.online_verification_attempted = true;
        self.candidate.online_verification_message = Some(result.message.clone());
        self
    }

    pub fn with_online_verification_context(
        mut self,
        attempted: bool,
        message: Option<String>,
    ) -> Self {
        self.candidate.online_verification_attempted = attempted;
        self.candidate.online_verification_message = message;
        self
    }

    pub fn build(self) -> TrustApprovalCandidate {
        self.candidate
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_candidate_test.rs"]
mod tests;
