// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Resolve explicit non-member signer allowance from CLI, environment, or config.
//!
//! This module keeps non-member acceptance policy aligned with
//! the standard CLI > environment > config > default precedence.

use std::path::Path;

use crate::config::types::ConfigKey;
use crate::{Error, Result};

use super::common::resolve_string_with_source;

const ENV_VAR: &str = "SECRETENV_ALLOW_NON_MEMBER";

/// Resolve whether read paths may prompt for one-shot non-member acceptance.
pub fn resolve_allow_non_member(cli_value: Option<bool>, base_dir: Option<&Path>) -> Result<bool> {
    if matches!(cli_value, Some(true)) {
        return Ok(true);
    }

    let resolved = resolve_string_with_source(
        None,
        Some(ENV_VAR),
        ConfigKey::AllowNonMember.canonical_name(),
        base_dir,
        Some("no".into()),
    )?;
    let value = resolved
        .map(|(value, _)| value)
        .unwrap_or_else(|| "no".to_string());
    parse_allow_non_member_value(&value)
}

fn parse_allow_non_member_value(value: &str) -> Result<bool> {
    if value.eq_ignore_ascii_case("yes") {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("no") {
        return Ok(false);
    }
    Err(Error::build_config_error(format!(
        "Invalid allow_non_member value '{}'. Expected 'yes' or 'no'.",
        value
    )))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_allow_non_member_test.rs"]
mod tests;
