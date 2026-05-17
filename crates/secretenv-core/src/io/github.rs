// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! GitHub API integration (HTTP helpers and account lookup).

#[cfg(feature = "online")]
pub mod account;
#[cfg(feature = "online")]
pub mod http;

#[cfg(not(feature = "online"))]
pub mod account {
    use crate::model::public_key::GithubAccount;
    use crate::{Error, Result};

    pub async fn resolve_github_account_by_login(
        login: &str,
        _verbose: bool,
    ) -> Result<GithubAccount> {
        Err(Error::build_config_error(format!(
            "GitHub account lookup for '{}' requires the 'online' feature",
            login
        )))
    }
}
