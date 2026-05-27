// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;

use crate::app_test_utils::build_test_command_options;
use crate::cli::common::command::{
    resolve_options_with_allow_expired_key, resolve_options_with_read_trust_allowances,
    resolve_required_member_handle_with_prompt,
};
use crate::cli::options::CommonOptions;
use crate::test_utils::EnvGuard;
use tempfile::TempDir;

fn save_global_config(temp_home: &TempDir, lines: &[&str]) {
    let config_path = temp_home.path().join("config.toml");
    fs::write(config_path, lines.join("\n")).unwrap();
}

#[test]
fn test_resolve_required_member_handle_with_prompt_uses_config_without_prompt() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", home.path());
    save_global_config(&home, &["member_handle = \"config-member\""]);
    let options = build_test_command_options(home.path(), None);

    let mut prompted = false;
    let member_handle =
        resolve_required_member_handle_with_prompt(&options, None, false, false, || {
            prompted = true;
            Ok("prompt-member".to_string())
        })
        .unwrap();

    assert_eq!(member_handle, "config-member");
    assert!(!prompted);
}

#[test]
fn test_resolve_required_member_handle_with_prompt_uses_prompt_when_enabled() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", home.path());
    let options = build_test_command_options(home.path(), None);

    let mut prompted = false;
    let member_handle =
        resolve_required_member_handle_with_prompt(&options, None, true, true, || {
            prompted = true;
            Ok("prompt-member".to_string())
        })
        .unwrap();

    assert_eq!(member_handle, "prompt-member");
    assert!(prompted);
}

#[test]
fn test_resolve_required_member_handle_with_prompt_errors_when_prompt_disabled() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", home.path());
    let options = build_test_command_options(home.path(), None);

    let error = resolve_required_member_handle_with_prompt(&options, None, false, true, || {
        panic!("prompt must not be called when prompting is disabled")
    })
    .unwrap_err();

    assert!(error
        .format_user_message()
        .contains("member handle not configured"));
    assert!(!error
        .format_user_message()
        .contains("Run in an interactive terminal for prompt"));
}

#[test]
fn test_resolve_required_member_handle_with_prompt_errors_with_hint_when_prompt_unavailable() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", home.path());
    let options = build_test_command_options(home.path(), None);

    let error = resolve_required_member_handle_with_prompt(&options, None, true, false, || {
        panic!("prompt must not be called when prompt is unavailable")
    })
    .unwrap_err();

    assert!(error
        .format_user_message()
        .contains("member handle not configured"));
    assert!(error
        .format_user_message()
        .contains("Run in an interactive terminal for prompt"));
}

#[test]
fn test_resolve_options_with_allow_expired_key_ignores_allow_non_member_config() {
    let _guard = EnvGuard::new(&[
        "SECRETENV_HOME",
        "SECRETENV_ALLOW_EXPIRED_KEY",
        "SECRETENV_ALLOW_NON_MEMBER",
    ]);
    let home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", home.path());
    env::set_var("SECRETENV_ALLOW_NON_MEMBER", "maybe");
    let options = common_options(home.path());

    let resolved = resolve_options_with_allow_expired_key(&options, false).unwrap();

    assert!(!resolved.allow_expired_key);
    assert!(!resolved.allow_non_member);
}

#[test]
fn test_resolve_options_with_read_trust_allowances_rejects_invalid_allow_non_member_config() {
    let _guard = EnvGuard::new(&[
        "SECRETENV_HOME",
        "SECRETENV_ALLOW_EXPIRED_KEY",
        "SECRETENV_ALLOW_NON_MEMBER",
    ]);
    let home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", home.path());
    env::set_var("SECRETENV_ALLOW_NON_MEMBER", "maybe");
    let options = common_options(home.path());

    let error = resolve_options_with_read_trust_allowances(&options, false, false).unwrap_err();

    assert!(error
        .format_user_message()
        .contains("Invalid allow_non_member value"));
}

fn common_options(home: &std::path::Path) -> CommonOptions {
    CommonOptions {
        home: Some(home.to_path_buf()),
        ..Default::default()
    }
}
