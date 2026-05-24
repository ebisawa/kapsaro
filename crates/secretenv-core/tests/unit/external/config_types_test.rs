// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for config value types.

use crate::test_utils::EnvGuard;
use secretenv_core::cli_api::test_support::settings::types::ConfigKey;
use secretenv_core::cli_api::test_support::storage::config::paths::get_global_config_path;
use std::path::PathBuf;

#[test]
fn test_config_xdg_path_resolution() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "HOME"]);
    std::env::set_var("SECRETENV_HOME", "/tmp/test-config");
    let path = get_global_config_path().unwrap();
    assert_eq!(path, PathBuf::from("/tmp/test-config/config.toml"));
}

#[test]
fn test_config_home_fallback() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "HOME"]);
    std::env::remove_var("SECRETENV_HOME");
    std::env::set_var("HOME", "/home/testuser");
    let path = get_global_config_path().unwrap();
    assert_eq!(
        path,
        PathBuf::from("/home/testuser/.config/secretenv/config.toml")
    );
}

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
}
