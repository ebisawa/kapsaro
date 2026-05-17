// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Blocking online verification facade.

use crate::io::github::account::resolve_github_account_by_login;
use crate::io::keystore::helpers::resolve_kid;
use crate::io::keystore::storage::load_public_key;
use crate::io::verify_online::github::preflight::verify_ssh_key_on_github;
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::model::public_key::GithubAccount as InternalGithubAccount;
use crate::support::runtime::block_on_result;
use crate::Result;

use super::key::LocalKeyStore;
use super::operation::OperationOptions;

/// GitHub account metadata used by online verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubAccount {
    id: u64,
    login: String,
}

/// Blocking GitHub online verification facade.
#[derive(Debug, Clone, Copy)]
pub struct GitHubOnlineVerifier {
    options: OperationOptions,
}

/// Online verification status returned by the facade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnlineVerificationStatus {
    NotConfigured,
    Verified,
    Failed,
}

/// Online verification result without raw document model exposure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlineVerificationResult {
    member_handle: String,
    status: OnlineVerificationStatus,
    message: String,
    fingerprint: Option<String>,
    matched_key_id: Option<i64>,
    github_claim_present: bool,
    verified_account: Option<GitHubAccount>,
}

impl GitHubOnlineVerifier {
    /// Build a blocking verifier from shared operation options.
    pub fn new(options: OperationOptions) -> Self {
        Self { options }
    }

    /// Resolve a GitHub account by login.
    pub fn resolve_account_by_login(&self, login: &str) -> Result<GitHubAccount> {
        block_on_result(resolve_github_account_by_login(login, self.options.debug()))
            .map(GitHubAccount::from_inner)
    }

    /// Verify that an SSH public key is registered on the GitHub account.
    pub fn verify_ssh_key(
        &self,
        account: &GitHubAccount,
        ssh_pubkey: &str,
    ) -> Result<OnlineVerificationStatus> {
        block_on_result(verify_ssh_key_on_github(
            ssh_pubkey,
            &account.to_inner(),
            self.options.debug(),
        ))
        .map(OnlineVerificationStatus::from)
    }

    /// Verify a member public key loaded from a local keystore.
    pub fn verify_keystore_member(
        &self,
        key_store: &LocalKeyStore,
        member_handle: &str,
        kid: Option<&str>,
        known_account: Option<&GitHubAccount>,
    ) -> Result<OnlineVerificationResult> {
        let resolved_kid = resolve_kid(key_store.root(), member_handle, kid)?;
        let public_key = load_public_key(key_store.root(), member_handle, &resolved_kid)?;
        let known_account = known_account.map(|account| (account.id, account.login.clone()));
        block_on_result(verify_github_account(
            &public_key,
            self.options.debug(),
            known_account,
        ))
        .map(OnlineVerificationResult::from)
    }

    /// Return shared operation options.
    pub fn options(&self) -> OperationOptions {
        self.options
    }
}

impl GitHubAccount {
    /// Build account metadata from GitHub's stable id and current login.
    pub fn new(id: u64, login: impl Into<String>) -> Self {
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

    fn to_inner(&self) -> InternalGithubAccount {
        InternalGithubAccount {
            id: self.id,
            login: self.login.clone(),
        }
    }
}

impl OnlineVerificationResult {
    /// Return the member handle from the verified public key.
    pub fn member_handle(&self) -> &str {
        &self.member_handle
    }

    /// Return the online verification status.
    pub fn status(&self) -> OnlineVerificationStatus {
        self.status
    }

    /// Return the user-facing verification message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Return the computed SSH key fingerprint when available.
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    /// Return the matched GitHub SSH key id when verification succeeded.
    pub fn matched_key_id(&self) -> Option<i64> {
        self.matched_key_id
    }

    /// Return whether the public key carried a GitHub binding claim.
    pub fn github_claim_present(&self) -> bool {
        self.github_claim_present
    }

    /// Return verified GitHub account metadata when verification succeeded.
    pub fn verified_account(&self) -> Option<&GitHubAccount> {
        self.verified_account.as_ref()
    }

    /// Return true when online verification succeeded.
    pub fn is_verified(&self) -> bool {
        self.status == OnlineVerificationStatus::Verified
    }
}

impl From<VerificationStatus> for OnlineVerificationStatus {
    fn from(value: VerificationStatus) -> Self {
        match value {
            VerificationStatus::NotConfigured => Self::NotConfigured,
            VerificationStatus::Verified => Self::Verified,
            VerificationStatus::Failed => Self::Failed,
        }
    }
}

impl From<VerificationResult> for OnlineVerificationResult {
    fn from(value: VerificationResult) -> Self {
        Self {
            member_handle: value.member_handle,
            status: OnlineVerificationStatus::from(value.status),
            message: value.message,
            fingerprint: value.fingerprint,
            matched_key_id: value.matched_key_id,
            github_claim_present: value.github_claim_present,
            verified_account: value
                .verified_github
                .map(|account| GitHubAccount::new(account.id, account.login)),
        }
    }
}
