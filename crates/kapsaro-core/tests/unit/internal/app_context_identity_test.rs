// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;

use crate::app::context::identity::{
    build_missing_member_handle_error, require_member_handle_input,
};
use crate::test_utils::EnvGuard;
use tempfile::TempDir;

fn setup_keystore(temp_dir: &TempDir, member_handles: &[&str]) {
    let keystore_root = temp_dir.path().join("keys");
    fs::create_dir_all(&keystore_root).unwrap();
    for &id in member_handles {
        fs::create_dir_all(keystore_root.join(id)).unwrap();
    }
}

#[test]
fn test_require_member_handle_input_errors_when_missing() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("KAPSARO_HOME", temp_home.path());
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
