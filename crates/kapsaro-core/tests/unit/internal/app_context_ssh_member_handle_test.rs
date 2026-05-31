// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::app::context::ssh::resolve_ssh_context_by_active_key;
use crate::app_test_utils::build_test_command_options;
use crate::test_utils::EnvGuard;
use tempfile::TempDir;

#[test]
fn test_resolve_ssh_context_by_active_key_honors_member_handle_option() {
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

    // With explicit member handle, we should not get the "multiple member handles found" config error.
    // It will still fail later because no active key exists for that member, which is expected.
    let err =
        match resolve_ssh_context_by_active_key(&options, Some("alice@example.com".to_string())) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
    let msg = format!("{err}");
    assert!(
        msg.contains("No active key for member"),
        "unexpected error: {msg}"
    );
}
