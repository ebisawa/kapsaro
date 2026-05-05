// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;

use crate::app::context::identity::{
    build_missing_member_handle_error, require_member_handle_input, resolve_github_user_input,
    resolve_member_handle_input,
};
use crate::test_utils::EnvGuard;
use tempfile::TempDir;

fn save_global_config(temp_home: &TempDir, lines: &[&str]) {
    let config_path = temp_home.path().join("config.toml");
    fs::write(config_path, lines.join("\n")).unwrap();
}

fn setup_keystore(temp_dir: &TempDir, member_handles: &[&str]) {
    let keystore_root = temp_dir.path().join("keys");
    fs::create_dir_all(&keystore_root).unwrap();
    for &id in member_handles {
        fs::create_dir_all(keystore_root.join(id)).unwrap();
    }
}

#[test]
fn test_resolve_member_handle_input_uses_fallback_sources() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    save_global_config(&temp_home, &["member_handle = \"config-member\""]);
    setup_keystore(&temp_home, &["keystore-member"]);

    let result = resolve_member_handle_input(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("config-member".to_string()));
}

#[test]
fn test_require_member_handle_input_errors_when_missing() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    setup_keystore(&temp_home, &[]);

    let error = require_member_handle_input(None, Some(temp_home.path()), false).unwrap_err();

    assert!(
        error
            .format_user_message()
            .contains("member handle is required but could not be determined"),
        "unexpected error: {}",
        error.format_user_message()
    );
}

#[test]
fn test_build_missing_member_handle_error_includes_prompt_hint_when_requested() {
    let error = build_missing_member_handle_error(true);

    assert!(error
        .format_user_message()
        .contains("Run in an interactive terminal for prompt"));
}

#[test]
fn test_resolve_github_user_input_uses_config_fallback() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    save_global_config(&temp_home, &["github_user = \"config-user\""]);

    let result = resolve_github_user_input(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("config-user".to_string()));
}
