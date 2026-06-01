// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Pre-flight SSH key verification against GitHub.
//!
//! Verifies that an SSH public key is registered on a GitHub user's account
//! before key generation. Does not require a PublicKey model.

use super::{GitHubVerificationApi, GitHubVerificationApiClient};
use crate::io::ssh::protocol::fingerprint;
use crate::io::verify_online::VerificationStatus;
use crate::model::public_key::GithubAccount;
use crate::{Error, Result};
use tracing::debug;

/// Verify that an SSH public key is registered on the specified GitHub account.
///
/// Returns `VerificationStatus::Verified` on success, or `Error::Verify` on failure.
pub async fn verify_ssh_key_on_github(
    ssh_pub_key: &str,
    account: &GithubAccount,
    verbose: bool,
) -> Result<VerificationStatus> {
    let api = GitHubVerificationApiClient::new()?;
    verify_ssh_key_on_github_with_api(ssh_pub_key, account, verbose, &api).await
}

/// Verify SSH key against GitHub with an injected API implementation.
pub async fn verify_ssh_key_on_github_with_api(
    ssh_pub_key: &str,
    account: &GithubAccount,
    verbose: bool,
    api: &impl GitHubVerificationApi,
) -> Result<VerificationStatus> {
    let our_fingerprint = fingerprint::build_sha256_fingerprint(ssh_pub_key)?;

    if verbose {
        debug!(
            "[VERIFY] Pre-flight: checking SSH key {} against GitHub user {}",
            our_fingerprint, account.login
        );
    }

    let github_keys = api.fetch_keys(&account.login).await?;

    if verbose {
        debug!(
            "[VERIFY] Pre-flight: fetched {} key(s) from GitHub",
            github_keys.len()
        );
    }

    for github_key in &github_keys {
        let Ok(github_fingerprint) = fingerprint::build_sha256_fingerprint(&github_key.key) else {
            continue;
        };
        if github_fingerprint == our_fingerprint {
            if verbose {
                debug!(
                    "[VERIFY] Pre-flight: fingerprint match (GitHub key id={})",
                    github_key.id
                );
            }
            return Ok(VerificationStatus::Verified);
        }
    }

    Err(Error::build_verification_error(
        "V-GITHUB-KEY-NEW".to_string(),
        format!(
            "SSH key not found on GitHub user '{}' (id={}, checked {} key(s), fingerprint={})",
            account.login,
            account.id,
            github_keys.len(),
            our_fingerprint
        ),
    ))
}
