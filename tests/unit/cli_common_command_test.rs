// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;

use crate::app_test_utils::build_test_command_options;
use crate::cli::common::command::resolve_required_member_id_with_prompt;
use crate::test_utils::EnvGuard;
use tempfile::TempDir;

fn write_global_config(temp_home: &TempDir, lines: &[&str]) {
    let config_path = temp_home.path().join("config.toml");
    fs::write(config_path, lines.join("\n")).unwrap();
}

#[test]
fn test_resolve_required_member_id_with_prompt_uses_config_without_prompt() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", home.path());
    write_global_config(&home, &["member_handle = \"config-member\""]);
    let options = build_test_command_options(home.path(), None);

    let mut prompted = false;
    let member_id = resolve_required_member_id_with_prompt(&options, None, false, false, || {
        prompted = true;
        Ok("prompt-member".to_string())
    })
    .unwrap();

    assert_eq!(member_id, "config-member");
    assert!(!prompted);
}

#[test]
fn test_resolve_required_member_id_with_prompt_uses_prompt_when_enabled() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", home.path());
    let options = build_test_command_options(home.path(), None);

    let mut prompted = false;
    let member_id = resolve_required_member_id_with_prompt(&options, None, true, true, || {
        prompted = true;
        Ok("prompt-member".to_string())
    })
    .unwrap();

    assert_eq!(member_id, "prompt-member");
    assert!(prompted);
}

#[test]
fn test_resolve_required_member_id_with_prompt_errors_when_prompt_disabled() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", home.path());
    let options = build_test_command_options(home.path(), None);

    let error = resolve_required_member_id_with_prompt(&options, None, false, true, || {
        panic!("prompt must not be called when prompting is disabled")
    })
    .unwrap_err();

    assert!(error
        .user_message()
        .contains("member handle not configured"));
    assert!(!error
        .user_message()
        .contains("Run in an interactive terminal for prompt"));
}

#[test]
fn test_resolve_required_member_id_with_prompt_errors_with_hint_when_prompt_unavailable() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_MEMBER_HANDLE"]);
    let home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", home.path());
    let options = build_test_command_options(home.path(), None);

    let error = resolve_required_member_id_with_prompt(&options, None, true, false, || {
        panic!("prompt must not be called when prompt is unavailable")
    })
    .unwrap_err();

    assert!(error
        .user_message()
        .contains("member handle not configured"));
    assert!(error
        .user_message()
        .contains("Run in an interactive terminal for prompt"));
}
