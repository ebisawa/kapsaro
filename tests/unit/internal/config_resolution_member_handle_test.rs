// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for config::resolution::member_handle::resolve_member_handle_with_fallback

use crate::test_utils::EnvGuard;
use serial_test::serial;
use std::env;
use std::fs;
use tempfile::TempDir;

fn save_global_config(temp_home: &TempDir, member_handle: &str) {
    let config_path = temp_home.path().join("config.toml");
    fs::write(
        config_path,
        format!("member_handle = \"{}\"\n", member_handle),
    )
    .unwrap();
}

fn setup_keystore(temp_dir: &TempDir, member_handles: &[&str]) {
    let keystore_root = temp_dir.path().join("keys");
    fs::create_dir_all(&keystore_root).unwrap();
    for &id in member_handles {
        fs::create_dir_all(keystore_root.join(id)).unwrap();
    }
}

#[test]
#[serial]
fn test_resolve_member_handle_from_cli_argument() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_HANDLE", "env-member");
    save_global_config(&temp_home, "config-member");
    setup_keystore(&temp_home, &["keystore-member"]);

    let result = super::resolve_member_handle_with_fallback(
        Some("cli-member".to_string()),
        Some(temp_home.path()),
    )
    .unwrap();

    assert_eq!(result, Some("cli-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_handle_cli_invalid_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    setup_keystore(&temp_home, &[]);

    let result = super::resolve_member_handle_with_fallback(
        Some("invalid member handle!".to_string()),
        Some(temp_home.path()),
    );

    assert!(result.is_err());
}

#[test]
#[serial]
fn test_resolve_member_handle_from_env_var() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_HANDLE", "env-member");
    save_global_config(&temp_home, "config-member");
    setup_keystore(&temp_home, &["keystore-member"]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("env-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_handle_env_invalid_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_HANDLE", "invalid member!");
    setup_keystore(&temp_home, &[]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path()));

    assert!(result.is_err());
}

#[test]
#[serial]
fn test_resolve_member_handle_from_global_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_HANDLE");
    save_global_config(&temp_home, "config-member");
    setup_keystore(&temp_home, &["keystore-member"]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("config-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_handle_config_invalid_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_HANDLE");
    save_global_config(&temp_home, "invalid member!");
    setup_keystore(&temp_home, &[]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path()));

    assert!(result.is_err());
}

#[test]
#[serial]
fn test_resolve_member_handle_from_keystore_single_member() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_HANDLE");
    setup_keystore(&temp_home, &["keystore-member"]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("keystore-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_handle_keystore_multiple_members_returns_none() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_HANDLE");
    setup_keystore(&temp_home, &["alice", "bob"]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_resolve_member_handle_keystore_empty_returns_none() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_HANDLE");
    setup_keystore(&temp_home, &[]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_resolve_member_handle_priority_cli_over_env() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_HANDLE", "env-member");
    setup_keystore(&temp_home, &[]);

    let result = super::resolve_member_handle_with_fallback(
        Some("cli-member".to_string()),
        Some(temp_home.path()),
    )
    .unwrap();

    assert_eq!(result, Some("cli-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_handle_priority_env_over_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_MEMBER_HANDLE", "env-member");
    save_global_config(&temp_home, "config-member");
    setup_keystore(&temp_home, &[]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("env-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_handle_priority_config_over_keystore() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_MEMBER_HANDLE");
    save_global_config(&temp_home, "config-member");
    setup_keystore(&temp_home, &["keystore-member"]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("config-member".to_string()));
}
