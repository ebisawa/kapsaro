// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! GitHub account resolution and preflight binding checks for key generation.
//! Confirms an SSH public key is already registered under the claimed account before proceeding.

use crate::io::github::account::resolve_github_account_by_login;
use crate::io::verify_online::github::preflight::verify_ssh_key_on_github;
use crate::model::public_key::GithubAccount;
use crate::service::online::OnlineVerificationStatus;
use crate::support::runtime::block_on_result;
use crate::Result;

pub fn resolve_github_account(github_user: Option<String>) -> Result<Option<GithubAccount>> {
    let Some(login) = github_user else {
        return Ok(None);
    };

    let account = block_on_result(resolve_github_account_by_login(&login))?;
    Ok(Some(account))
}

/// Verify SSH public key is registered on GitHub before key generation.
pub fn verify_preflight_github_binding(
    ssh_pub_key: &str,
    account: &GithubAccount,
) -> Result<OnlineVerificationStatus> {
    let status = block_on_result(verify_ssh_key_on_github(ssh_pub_key, account))?;
    Ok(OnlineVerificationStatus::from(status))
}
