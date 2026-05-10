// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::EnvGuard;
use serial_test::serial;
use std::env;
use std::fs;

#[test]
#[serial]
fn test_resolve_github_user_from_cli() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_GITHUB_USER", "env-user");

    let result = super::resolve_github_user(Some("cli-user".to_string()), None).unwrap();
    assert_eq!(result, Some("cli-user".to_string()));
}

#[test]
#[serial]
fn test_resolve_github_user_from_env() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_GITHUB_USER", "env-user");

    let result = super::resolve_github_user(None, None).unwrap();
    assert_eq!(result, Some("env-user".to_string()));
}

#[test]
#[serial]
fn test_resolve_github_user_from_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_GITHUB_USER");

    let config_path = temp_home.path().join("config.toml");
    fs::write(&config_path, "github_user = \"config-user\"\n").unwrap();

    let result = super::resolve_github_user(None, None).unwrap();
    assert_eq!(result, Some("config-user".to_string()));
}

#[test]
#[serial]
fn test_resolve_github_user_none_when_no_source() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_GITHUB_USER");

    let result = super::resolve_github_user(None, None).unwrap();
    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_resolve_github_user_rejects_invalid_cli_value() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    let result = super::resolve_github_user(Some("../alice".to_string()), None);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_resolve_github_user_rejects_invalid_env_value() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_GITHUB_USER", "alice?tab=keys");

    let result = super::resolve_github_user(None, None);
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_resolve_github_user_rejects_invalid_config_value() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::remove_var("SECRETENV_GITHUB_USER");

    let config_path = temp_home.path().join("config.toml");
    fs::write(&config_path, "github_user = \"alice#keys\"\n").unwrap();

    let result = super::resolve_github_user(None, None);
    assert!(result.is_err());
}
