// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for config value types.

use crate::config::types::ConfigKey;

#[test]
fn test_config_key_supported_names_match_global_config_surface() {
    assert_eq!(
        ConfigKey::canonical_names(),
        &[
            "member_handle",
            "workspace",
            "ssh_identity",
            "ssh_keygen_command",
            "ssh_add_command",
            "ssh_signing_method",
            "github_user",
            "allow_expired_key",
            "allow_non_member",
        ]
    );
}

#[test]
fn test_config_key_normalizes_github_user_typo_alias() {
    let key = ConfigKey::parse("gihub_user").unwrap();

    assert_eq!(key.canonical_name(), "github_user");
}

#[test]
fn test_config_key_error_lists_supported_names() {
    let error = ConfigKey::parse("unknown").unwrap_err();
    let message = error.to_string();

    assert!(message.contains("invalid key 'unknown'"));
    assert!(message.contains("member_handle"));
    assert!(message.contains("allow_expired_key"));
    assert!(message.contains("allow_non_member"));
}
