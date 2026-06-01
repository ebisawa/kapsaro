// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared trust approval candidate construction.

use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::io::verify_online::{VerificationResult, VerifiedGithubIdentity};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;

/// Review material for a manual trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustApprovalCandidate {
    pub member_handle: MemberHandle,
    pub kid: Kid,
    pub fingerprint: Option<String>,
    pub github_id: Option<u64>,
    pub github_login: Option<String>,
    pub attestor_pub: Option<String>,
    pub verified_github: Option<VerifiedGithubIdentity>,
    pub github_binding_configured: bool,
    pub online_verification_attempted: bool,
    pub online_verification_message: Option<String>,
    pub public_key: Option<PublicKey>,
    pub requires_out_of_band_verification: bool,
}

pub struct TrustApprovalCandidateBuilder {
    candidate: TrustApprovalCandidate,
}

impl TrustApprovalCandidateBuilder {
    pub fn new(member_handle: &str, kid: &str) -> Self {
        Self {
            candidate: TrustApprovalCandidate {
                member_handle: MemberHandle::try_from(member_handle.to_string())
                    .expect("trust approval candidate member_handle must be valid"),
                kid: Kid::try_from(kid.to_string())
                    .expect("trust approval candidate kid must be valid"),
                fingerprint: None,
                github_id: None,
                github_login: None,
                attestor_pub: None,
                verified_github: None,
                github_binding_configured: false,
                online_verification_attempted: false,
                online_verification_message: None,
                public_key: None,
                requires_out_of_band_verification: true,
            },
        }
    }

    pub fn from_public_key(public_key: &PublicKey) -> Self {
        Self::new(
            &public_key.protected.subject_handle,
            &public_key.protected.kid,
        )
        .with_fingerprint(build_attestation_fingerprint(public_key))
        .with_attestor_pub(Some(public_key.protected.attestation.pub_.clone()))
        .with_github_binding_configured(github_binding_configured(public_key))
        .with_public_key(Some(public_key.clone()))
    }

    pub fn with_fingerprint(mut self, fingerprint: Option<String>) -> Self {
        self.candidate.fingerprint = fingerprint;
        self
    }

    pub fn with_attestor_pub(mut self, attestor_pub: Option<String>) -> Self {
        self.candidate.attestor_pub = attestor_pub;
        self
    }

    pub fn with_github_binding_configured(mut self, configured: bool) -> Self {
        self.candidate.github_binding_configured = configured;
        self
    }

    pub fn with_verified_github(mut self, verified_github: Option<VerifiedGithubIdentity>) -> Self {
        let (github_id, github_login) = derive_github_review_fields(verified_github.as_ref());
        self.candidate.verified_github = verified_github;
        self.candidate.github_id = github_id;
        self.candidate.github_login = github_login;
        self
    }

    pub fn with_github_review_fields(
        mut self,
        github_id: Option<u64>,
        github_login: Option<String>,
    ) -> Self {
        self.candidate.github_id = github_id;
        self.candidate.github_login = github_login;
        self
    }

    pub fn with_public_key(mut self, public_key: Option<PublicKey>) -> Self {
        self.candidate.public_key = public_key;
        self
    }

    pub fn with_verification_result(mut self, result: &VerificationResult) -> Self {
        self.candidate.fingerprint = result
            .fingerprint
            .clone()
            .or_else(|| self.candidate.fingerprint.clone());
        self = self.with_verified_github(result.verified_github.clone());
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

fn build_attestation_fingerprint(public_key: &PublicKey) -> Option<String> {
    build_sha256_fingerprint(&public_key.protected.attestation.pub_).ok()
}

fn github_binding_configured(public_key: &PublicKey) -> bool {
    public_key
        .protected
        .binding_claims
        .as_ref()
        .and_then(|claims| claims.github_account.as_ref())
        .is_some()
}

fn derive_github_review_fields(
    verified_github: Option<&VerifiedGithubIdentity>,
) -> (Option<u64>, Option<String>) {
    match verified_github {
        Some(account) => (Some(account.id), Some(account.login.clone())),
        None => (None, None),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_candidate_test.rs"]
mod tests;
