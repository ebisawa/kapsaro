// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Resolve explicit expired-key allowance from CLI, environment, or config.
//!
//! This module keeps operational expired-key policy resolution aligned with
//! the standard CLI > environment > config > default precedence.

use std::path::Path;

use crate::config::types::ConfigKey;
use crate::{Error, Result};

use super::common::resolve_string_with_source;

const ENV_VAR: &str = "KAPSARO_ALLOW_EXPIRED_KEY";

/// Resolve whether operational paths may use expired keys.
pub fn resolve_allow_expired_key(cli_value: Option<bool>, base_dir: Option<&Path>) -> Result<bool> {
    if matches!(cli_value, Some(true)) {
        return Ok(true);
    }

    let resolved = resolve_string_with_source(
        None,
        Some(ENV_VAR),
        ConfigKey::AllowExpiredKey.canonical_name(),
        base_dir,
        Some("no".into()),
    )?;
    let value = resolved
        .map(|(value, _)| value)
        .unwrap_or_else(|| "no".to_string());
    parse_allow_expired_key_value(&value)
}

fn parse_allow_expired_key_value(value: &str) -> Result<bool> {
    if value.eq_ignore_ascii_case("yes") {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("no") {
        return Ok(false);
    }
    Err(Error::build_config_error(format!(
        "Invalid allow_expired_key value '{}'. Expected 'yes' or 'no'.",
        value
    )))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_allow_expired_key_test.rs"]
mod tests;
