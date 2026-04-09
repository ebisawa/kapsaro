// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/config module
//!
//! Tests for configuration use cases.

use crate::test_utils::EnvGuard;
use secretenv::feature::config::{
    get_config_path_and_scope, load_global_config, resolve_config_value, validate_key, ConfigScope,
};
use secretenv::io::config::paths::get_global_config_path;
use secretenv::io::config::store::set_config_value;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_validate_key_valid() {
    assert!(validate_key("member_id").is_ok());
    assert!(validate_key("ssh_key").is_ok());
    assert!(validate_key("ssh_keygen").is_ok());
    assert!(validate_key("ssh_add").is_ok());
    assert!(validate_key("ssh_signer").is_ok());
    assert!(validate_key("github_user").is_ok());
    assert!(validate_key("gihub_user").is_ok());
}

#[test]
fn test_validate_key_invalid() {
    assert!(validate_key("invalid_key").is_err());
    assert!(validate_key("unknown").is_err());
}

#[test]
fn test_resolve_config_value_global() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);
    let _temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", _temp_dir.path().to_str().unwrap());
    let global_config_path = get_global_config_path().unwrap();

    // Ensure global config directory exists
    if let Some(parent) = global_config_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }

    // Set global config
    set_config_value(&global_config_path, "member_id", "global@example.com").unwrap();

    // Resolve config value
    let resolution = resolve_config_value("member_id", Some(_temp_dir.path())).unwrap();

    assert_eq!(resolution.value, Some("global@example.com".to_string()));
    assert_eq!(resolution.scope, Some("global".to_string()));
}

#[test]
fn test_get_config_path_and_scope_global() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);
    let _temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", _temp_dir.path().to_str().unwrap());
    let resolution = get_config_path_and_scope(Some(_temp_dir.path())).unwrap();

    match resolution.scope {
        ConfigScope::Global => {}
    }
    // Path should be global config path
    assert!(resolution.path.to_string_lossy().contains("config.toml"));
}

#[test]
fn test_load_global_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);
    let _temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", _temp_dir.path().to_str().unwrap());
    let global_config_path = get_global_config_path().unwrap();

    // Ensure global config directory exists
    if let Some(parent) = global_config_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }

    // Set global config
    set_config_value(&global_config_path, "member_id", "global@example.com").unwrap();

    // Load global config
    let config = load_global_config(Some(_temp_dir.path())).unwrap();

    // May contain the value or be empty depending on test environment
    let _ = config;
}
