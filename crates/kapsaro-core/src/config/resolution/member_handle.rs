// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member handle resolution
//!
//! Resolves the member handle based on the following priority order:
//! 1. CLI argument (--member-handle)
//! 2. Environment variable (KAPSARO_MEMBER_HANDLE)
//! 3. Global config (KAPSARO_HOME/config.toml)
//! 4. Single member entry in keystore

use crate::io::config as io_config;
use crate::io::keystore::member::load_single_member_handle_from_keystore;
use crate::io::keystore::paths;
use crate::support::validation;
use crate::Result;
use std::path::Path;

use super::common::resolve_string_with_priority;
use crate::config::types::ConfigKey;

/// Resolve the member handle from non-interactive sources and return `None` when unresolved.
pub(crate) fn resolve_member_handle_with_fallback(
    member_handle_opt: Option<String>,
    base_dir: Option<&Path>,
) -> Result<Option<String>> {
    // Priority 1-3: Use common resolution logic
    if let Some(member_handle) = resolve_string_with_priority(
        member_handle_opt,
        Some("KAPSARO_MEMBER_HANDLE"),
        ConfigKey::MemberHandle.canonical_name(),
        base_dir,
        None,
    )? {
        validation::validate_member_handle(&member_handle)?;
        return Ok(Some(member_handle));
    }

    // Priority 4: Single member handle in keystore
    resolve_optional_member_handle_from_keystore(base_dir)
}

fn resolve_optional_member_handle_from_keystore(base_dir: Option<&Path>) -> Result<Option<String>> {
    let keystore_root = match base_dir {
        Some(dir) => paths::get_keystore_root_from_base(dir),
        None => {
            let base = io_config::paths::get_base_dir()?;
            paths::get_keystore_root_from_base(&base)
        }
    };

    load_single_member_handle_from_keystore(&keystore_root)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_member_handle_test.rs"]
mod tests;
