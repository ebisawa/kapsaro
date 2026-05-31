// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::verification::OnlineVerificationStatus;
use crate::io::github::account::resolve_github_account_by_login;
use crate::io::verify_online::github::preflight::verify_ssh_key_on_github;
use crate::model::public_key::GithubAccount;
use crate::support::runtime::block_on_result;
use crate::Result;

pub fn resolve_github_account(
    github_user: Option<String>,
    verbose: bool,
) -> Result<Option<GithubAccount>> {
    let Some(login) = github_user else {
        return Ok(None);
    };

    let account = block_on_result(resolve_github_account_by_login(&login, verbose))?;
    Ok(Some(account))
}

/// Verify SSH public key is registered on GitHub before key generation.
pub fn verify_preflight_github_binding(
    ssh_pub_key: &str,
    account: &GithubAccount,
    verbose: bool,
) -> Result<OnlineVerificationStatus> {
    let status = block_on_result(verify_ssh_key_on_github(ssh_pub_key, account, verbose))?;
    Ok(OnlineVerificationStatus::from(status))
}
