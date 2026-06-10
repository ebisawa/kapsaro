// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/config module
//!
//! Tests for configuration use cases.

use crate::config::resolution::global::{
    resolve_config_location, resolve_config_value, validate_key, ConfigScope,
};
use crate::io::config::paths::get_global_config_path;
use crate::io::config::store::set_config_value;
use crate::test_utils::EnvGuard;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_validate_key_valid() {
    assert!(validate_key("member_handle").is_ok());
    assert!(validate_key("workspace").is_ok());
    assert!(validate_key("ssh_identity").is_ok());
    assert!(validate_key("ssh_keygen_command").is_ok());
    assert!(validate_key("ssh_add_command").is_ok());
    assert!(validate_key("ssh_signing_method").is_ok());
    assert!(validate_key("github_user").is_ok());
    assert!(validate_key("allow_expired_key").is_ok());
}

#[test]
fn test_validate_key_invalid() {
    assert!(validate_key("invalid_key").is_err());
    assert!(validate_key("unknown").is_err());
}

#[test]
fn test_resolve_config_value_global() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME"]);
    let _temp_dir = TempDir::new().unwrap();
    std::env::set_var("KAPSARO_HOME", _temp_dir.path().to_str().unwrap());
    let global_config_path = get_global_config_path().unwrap();

    // Ensure global config directory exists
    if let Some(parent) = global_config_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }

    // Set global config
    set_config_value(&global_config_path, "member_handle", "global@example.com").unwrap();

    // Resolve config value
    let resolution = resolve_config_value("member_handle", Some(_temp_dir.path())).unwrap();

    assert_eq!(resolution.value, Some("global@example.com".to_string()));
    assert_eq!(resolution.scope, Some("global".to_string()));
}

#[test]
fn test_resolve_workspace_config_value_global() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME"]);
    let _temp_dir = TempDir::new().unwrap();
    std::env::set_var("KAPSARO_HOME", _temp_dir.path().to_str().unwrap());
    let global_config_path = get_global_config_path().unwrap();

    if let Some(parent) = global_config_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }

    set_config_value(&global_config_path, "workspace", "~/workspace/.kapsaro").unwrap();

    let resolution = resolve_config_value("workspace", Some(_temp_dir.path())).unwrap();

    assert_eq!(resolution.value, Some("~/workspace/.kapsaro".to_string()));
    assert_eq!(resolution.scope, Some("global".to_string()));
}

#[test]
fn test_resolve_config_location_global() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME"]);
    let _temp_dir = TempDir::new().unwrap();
    std::env::set_var("KAPSARO_HOME", _temp_dir.path().to_str().unwrap());
    let resolution = resolve_config_location(Some(_temp_dir.path())).unwrap();

    match resolution.scope {
        ConfigScope::Global => {}
    }
    // Path should be global config path
    assert!(resolution.path.to_string_lossy().contains("config.toml"));
}
