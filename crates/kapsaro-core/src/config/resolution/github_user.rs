// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! GitHub user resolution
//!
//! Resolves github_user based on the following priority order:
//! 1. CLI argument (--github-user)
//! 2. Environment variable (KAPSARO_GITHUB_USER)
//! 3. Global config (KAPSARO_HOME/config.toml)

use crate::support::validation;
use crate::Result;
#[cfg(test)]
use std::path::Path;

use super::common::resolve_string_with_priority;
use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::config::types::ConfigKey;

/// Resolve github_user based on priority order
///
/// # Priority Order
///
/// 1. `cli_value` parameter (CLI argument)
/// 2. `KAPSARO_GITHUB_USER` environment variable
/// 3. Global config (`KAPSARO_HOME/config.toml`)
///
/// Returns `None` if no source provides a value.
#[cfg(test)]
pub(crate) fn resolve_github_user(
    cli_value: Option<String>,
    base_dir: Option<&Path>,
) -> Result<Option<String>> {
    resolve_github_user_with_config(cli_value, &GlobalConfigSnapshot::for_base_dir(base_dir))
}

pub(crate) fn resolve_github_user_with_config(
    cli_value: Option<String>,
    config: &GlobalConfigSnapshot,
) -> Result<Option<String>> {
    let github_user = resolve_string_with_priority(
        cli_value,
        Some("KAPSARO_GITHUB_USER"),
        ConfigKey::GithubUser.canonical_name(),
        config,
        None,
    )?;
    if let Some(login) = github_user.as_deref() {
        validation::validate_github_login(login)?;
    }
    Ok(github_user)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_github_user_test.rs"]
mod tests;
