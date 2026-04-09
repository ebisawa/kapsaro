// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Online verification for binding_claims.github_account
//!
//! Implements GitHub API integration for verifying SSH key ownership.

pub mod github;

/// Status of online verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VerificationStatus {
    /// Verification succeeded — key matched on external service.
    Verified,
    /// Verification failed — key did not match or API error.
    Failed,
    /// Verification not configured — no binding_claims or invalid attestation.
    NotConfigured,
}

/// GitHub identity verified by online verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGithubIdentity {
    pub id: u64,
    pub login: String,
    pub fingerprint: String,
    pub matched_key_id: i64,
}

impl VerifiedGithubIdentity {
    pub fn new(id: u64, login: String, fingerprint: String, matched_key_id: i64) -> Self {
        Self {
            id,
            login,
            fingerprint,
            matched_key_id,
        }
    }
}

/// Verification result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationResult {
    pub member_id: String,
    pub status: VerificationStatus,
    pub message: String,
    pub fingerprint: Option<String>,
    pub matched_key_id: Option<i64>,
    pub github_claim_present: bool,
    /// When verification succeeded, the verified GitHub identity (not serialized)
    #[serde(skip)]
    pub verified_github: Option<VerifiedGithubIdentity>,
}

impl VerificationResult {
    /// Create a result for when verification is not configured / skipped.
    pub(crate) fn not_configured(
        member_id: &str,
        message: &str,
        fingerprint: Option<String>,
        github_claim_present: bool,
    ) -> Self {
        Self {
            member_id: member_id.to_string(),
            status: VerificationStatus::NotConfigured,
            message: message.to_string(),
            fingerprint,
            matched_key_id: None,
            github_claim_present,
            verified_github: None,
        }
    }

    /// Create a failed verification result.
    pub(crate) fn failed(
        member_id: &str,
        message: String,
        fingerprint: Option<String>,
        github_claim_present: bool,
    ) -> Self {
        Self {
            member_id: member_id.to_string(),
            status: VerificationStatus::Failed,
            message,
            fingerprint,
            matched_key_id: None,
            github_claim_present,
            verified_github: None,
        }
    }

    /// Create a successful verification result.
    pub(crate) fn verified(
        member_id: &str,
        message: String,
        verified_github: VerifiedGithubIdentity,
    ) -> Self {
        Self {
            member_id: member_id.to_string(),
            status: VerificationStatus::Verified,
            message,
            fingerprint: Some(verified_github.fingerprint.clone()),
            matched_key_id: Some(verified_github.matched_key_id),
            github_claim_present: true,
            verified_github: Some(verified_github),
        }
    }

    /// Returns `true` if verification succeeded.
    pub fn is_verified(&self) -> bool {
        self.status == VerificationStatus::Verified
    }
}
