// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::app::context::ssh::resolve_ssh_context_for_member_key;
use crate::app_test_utils::build_test_command_options;
use crate::test_utils::EnvGuard;
use tempfile::TempDir;

#[test]
fn test_resolve_ssh_context_for_member_key_honors_member_handle_option() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let stale_home = TempDir::new().unwrap();
    let stale_home_path = stale_home.path().to_path_buf();
    drop(stale_home);
    std::env::set_var("KAPSARO_HOME", stale_home_path);
    std::env::remove_var("KAPSARO_WORKSPACE");

    let base_dir = TempDir::new().unwrap();

    // Create a keystore with multiple member directories.
    // This would normally require --member-handle (or config/env) to disambiguate.
    let keys_dir = base_dir.path().join("keys");
    fs::create_dir_all(keys_dir.join("alice@example.com")).unwrap();
    fs::create_dir_all(keys_dir.join("bob@example.com")).unwrap();

    let options = build_test_command_options(base_dir.path(), None);

    // With an explicit member handle, key resolution reaches that member even
    // though another member directory exists beside it.
    let err = match resolve_ssh_context_for_member_key(
        &options,
        Some("alice@example.com".to_string()),
        None,
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("No keys found for member"),
        "unexpected error: {msg}"
    );
}
