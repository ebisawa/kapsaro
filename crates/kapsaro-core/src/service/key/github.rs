// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! GitHub account resolution and preflight binding checks for key generation.
//! Confirms an SSH public key is already registered under the claimed account before proceeding.

use crate::service::online::{GitHubAccount, GitHubOnlineVerifier, OnlineVerificationStatus};
use crate::Result;

/// Look up the account a key generation claims to bind to, if one was claimed.
pub fn resolve_github_account(github_user: Option<String>) -> Result<Option<GitHubAccount>> {
    let Some(login) = github_user else {
        return Ok(None);
    };

    let account = GitHubOnlineVerifier::new().resolve_account_by_login(&login)?;
    Ok(Some(account))
}

/// Verify SSH public key is registered on GitHub before key generation.
pub fn verify_preflight_github_binding(
    ssh_pub_key: &str,
    account: &GitHubAccount,
) -> Result<OnlineVerificationStatus> {
    GitHubOnlineVerifier::new().verify_ssh_key(account, ssh_pub_key)
}
