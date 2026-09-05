// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Standard blocking online verification operations.

use crate::io::github::account::resolve_github_account_by_login;
use crate::io::verify_online::github::preflight::verify_ssh_key_on_github;
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus, VerifiedGithubIdentity};
use crate::model::public_key::GithubAccount as InternalGithubAccount;
use crate::support::runtime::block_on_result;
use crate::Result;

use super::trust::KnownKeyReviewCandidate;

/// Application-facing online verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum OnlineVerificationStatus {
    /// Online verification is not configured.
    NotConfigured,
    /// Online verification succeeded.
    Verified,
    /// Online verification failed.
    Failed,
}

impl OnlineVerificationStatus {
    /// Return whether online verification succeeded.
    pub fn is_verified(self) -> bool {
        self == Self::Verified
    }
}

impl From<crate::io::verify_online::VerificationStatus> for OnlineVerificationStatus {
    fn from(value: crate::io::verify_online::VerificationStatus) -> Self {
        match value {
            crate::io::verify_online::VerificationStatus::NotConfigured => Self::NotConfigured,
            crate::io::verify_online::VerificationStatus::Verified => Self::Verified,
            crate::io::verify_online::VerificationStatus::Failed => Self::Failed,
        }
    }
}

/// GitHub account metadata used by online verification.
///
/// Values are returned by GitHub lookup or successful verification. Callers
/// cannot construct arbitrary id/login pairs.
///
/// ```compile_fail
/// use kapsaro_core::api::online::GitHubAccount;
///
/// let _account = GitHubAccount::new(42, "alice");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubAccount {
    id: u64,
    login: String,
}

/// Blocking GitHub online verification facade.
#[derive(Debug, Clone, Copy, Default)]
pub struct GitHubOnlineVerifier;

/// GitHub evidence produced only by successful candidate verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGitHubEvidence {
    account: GitHubAccount,
    fingerprint: String,
    matched_key_id: i64,
    subject_handle: super::key::MemberHandle,
    kid: super::key::Kid,
    ssh_attestor_public_key: String,
}

impl GitHubOnlineVerifier {
    /// Build a blocking verifier.
    pub fn new() -> Self {
        Self
    }

    /// Resolve a GitHub account by login.
    pub fn resolve_account_by_login(&self, login: &str) -> Result<GitHubAccount> {
        block_on_result(resolve_github_account_by_login(login)).map(GitHubAccount::from_inner)
    }

    /// Verify that an SSH public key is registered on the GitHub account.
    pub fn verify_ssh_key(
        &self,
        account: &GitHubAccount,
        ssh_pubkey: &str,
    ) -> Result<OnlineVerificationStatus> {
        block_on_result(verify_ssh_key_on_github(ssh_pubkey, &account.to_inner()))
            .map(OnlineVerificationStatus::from)
    }

    /// Verify the candidate's claimed account and attestor key using GitHub.
    pub fn verify_known_key_candidate(
        &self,
        candidate: &KnownKeyReviewCandidate,
    ) -> Result<VerifiedGitHubEvidence> {
        let result = block_on_result(verify_github_account(candidate.public_key()))?;
        VerifiedGitHubEvidence::from_result(candidate, result)
    }
}

impl GitHubAccount {
    fn new(id: u64, login: impl Into<String>) -> Self {
        Self {
            id,
            login: login.into(),
        }
    }

    /// Return the GitHub account id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Return the GitHub login.
    pub fn login(&self) -> &str {
        &self.login
    }

    fn from_inner(account: InternalGithubAccount) -> Self {
        Self::new(account.id, account.login)
    }

    /// Return the wire form a generated key document records the binding as.
    pub(crate) fn to_inner(&self) -> InternalGithubAccount {
        InternalGithubAccount {
            id: self.id,
            login: self.login.clone(),
        }
    }
}

impl VerifiedGitHubEvidence {
    #[cfg(any(test, feature = "cli-test-support"))]
    pub(crate) fn for_test(
        candidate: &KnownKeyReviewCandidate,
        id: u64,
        login: impl Into<String>,
        fingerprint: impl Into<String>,
        matched_key_id: i64,
    ) -> Self {
        Self {
            account: GitHubAccount::new(id, login),
            fingerprint: fingerprint.into(),
            matched_key_id,
            subject_handle: candidate.subject_handle().clone(),
            kid: candidate.kid().clone(),
            ssh_attestor_public_key: candidate.ssh_attestor_public_key().to_string(),
        }
    }

    pub(crate) fn from_result(
        candidate: &KnownKeyReviewCandidate,
        result: VerificationResult,
    ) -> Result<Self> {
        if result.status != VerificationStatus::Verified {
            return Err(crate::Error::build_verification_error(
                "E_ONLINE_VERIFICATION_FAILED".to_string(),
                result.message,
            ));
        }
        let verified = result.verified_github.ok_or_else(|| {
            crate::Error::build_verification_error(
                "E_ONLINE_VERIFICATION_FAILED".to_string(),
                "Successful GitHub verification did not return verified identity evidence"
                    .to_string(),
            )
        })?;
        enforce_reviewed_candidate_identity(candidate, &result.member_handle, &verified)?;
        enforce_result_matches_identity(
            result.fingerprint.as_deref(),
            result.matched_key_id,
            &verified,
        )?;
        Ok(Self {
            account: GitHubAccount::new(verified.id, verified.login),
            fingerprint: verified.fingerprint,
            matched_key_id: verified.matched_key_id,
            subject_handle: candidate.subject_handle().clone(),
            kid: candidate.kid().clone(),
            ssh_attestor_public_key: candidate.ssh_attestor_public_key().to_string(),
        })
    }

    /// Return the verified GitHub account.
    pub fn account(&self) -> &GitHubAccount {
        &self.account
    }

    /// Return the fingerprint matched by GitHub.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Return the matching GitHub SSH key record ID.
    pub fn matched_key_id(&self) -> i64 {
        self.matched_key_id
    }

    pub(crate) fn matches_candidate(&self, candidate: &KnownKeyReviewCandidate) -> bool {
        self.subject_handle == *candidate.subject_handle()
            && self.kid == *candidate.kid()
            && self.ssh_attestor_public_key == candidate.ssh_attestor_public_key()
            && candidate.github_account_id() == Some(self.account.id())
    }
}

/// Refuse evidence that does not describe the exact candidate under review.
fn enforce_reviewed_candidate_identity(
    candidate: &KnownKeyReviewCandidate,
    member_handle: &str,
    verified: &VerifiedGithubIdentity,
) -> Result<()> {
    if member_handle != candidate.subject_handle().as_str() {
        return Err(crate::Error::build_verification_error(
            "E_ONLINE_VERIFICATION_IDENTITY_MISMATCH".to_string(),
            "GitHub verification result belongs to a different member".to_string(),
        ));
    }
    if candidate.github_account_id() != Some(verified.id) {
        return Err(crate::Error::build_verification_error(
            "E_ONLINE_VERIFICATION_IDENTITY_MISMATCH".to_string(),
            "Verified GitHub account id differs from the reviewed binding claim".to_string(),
        ));
    }
    if candidate.fingerprint() != Some(verified.fingerprint.as_str()) {
        return Err(build_evidence_mismatch_error(
            "Verified SSH fingerprint differs from the reviewed candidate",
        ));
    }
    Ok(())
}

/// Refuse a result whose own fields disagree with the identity it carries.
fn enforce_result_matches_identity(
    fingerprint: Option<&str>,
    matched_key_id: Option<i64>,
    verified: &VerifiedGithubIdentity,
) -> Result<()> {
    if fingerprint != Some(verified.fingerprint.as_str()) {
        return Err(build_evidence_mismatch_error(
            "Verification result fingerprint differs from its verified identity",
        ));
    }
    if matched_key_id != Some(verified.matched_key_id) {
        return Err(build_evidence_mismatch_error(
            "Verification result matched key id differs from its verified identity",
        ));
    }
    Ok(())
}

fn build_evidence_mismatch_error(message: &str) -> crate::Error {
    crate::Error::build_verification_error(
        "E_ONLINE_VERIFICATION_EVIDENCE_MISMATCH".to_string(),
        message.to_string(),
    )
}

#[cfg(test)]
#[path = "../../tests/unit/internal/service_online_test.rs"]
mod service_online_test;
