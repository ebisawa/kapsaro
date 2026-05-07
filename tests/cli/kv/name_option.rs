// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `-n <name>` option in KV commands
//!
//! Tests that `-n` correctly resolves to `<workspace>/secrets/<name>.kvenc`
//! and that omitting `-n` defaults to `default.kvenc`.

use crate::cli::common::{cmd, set_value_with_member_set_review, setup_workspace};
use predicates::prelude::*;

// ============================================================================
// set -n tests
// ============================================================================

/// Test: `set -n staging KEY VALUE` creates `staging.kvenc`
#[test]
fn test_set_with_name_option_creates_named_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let staging_file = workspace_dir.path().join("secrets").join("staging.kvenc");

    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "STAGING_KEY",
        "staging_value",
        None,
        Some("staging"),
    );

    assert!(staging_file.exists(), "staging.kvenc should be created");

    // default.kvenc should NOT be created
    let default_file = workspace_dir.path().join("secrets").join("default.kvenc");
    assert!(
        !default_file.exists(),
        "default.kvenc should not be created when -n staging is used"
    );
}

/// Test: `set` without `-n` defaults to `default.kvenc`
#[test]
fn test_set_without_name_option_defaults_to_default() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let default_file = workspace_dir.path().join("secrets").join("default.kvenc");

    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "MY_KEY",
        "my_value",
        None,
        None,
    );

    assert!(
        default_file.exists(),
        "default.kvenc should be created when -n is omitted"
    );
}

// ============================================================================
// set + get -n roundtrip test
// ============================================================================

/// Test: `set -n myfile KEY VALUE` and `get -n myfile KEY` roundtrip
#[test]
fn test_set_get_with_name_option_roundtrip() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set in custom file
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "MY_KEY",
        "my_secret_value",
        None,
        Some("myfile"),
    );

    // Get from custom file
    cmd()
        .arg("get")
        .arg("-n")
        .arg("myfile")
        .arg("MY_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("my_secret_value"));
}

// ============================================================================
// list -n tests
// ============================================================================

/// Test: `list -n myfile` shows keys from custom file
#[test]
fn test_list_with_name_option() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set in custom file
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "PROD_KEY",
        "prod_value",
        None,
        Some("prod"),
    );

    // List from custom file
    cmd()
        .arg("list")
        .arg("-n")
        .arg("prod")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("PROD_KEY"));
}

// ============================================================================
// unset -n tests
// ============================================================================

/// Test: `unset -n myfile KEY` removes key from named file; subsequent `get -n myfile KEY` fails
#[test]
fn test_unset_with_name_option() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set key in custom file
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "REMOVE_KEY",
        "remove_value",
        None,
        Some("myfile"),
    );

    // Unset key from custom file
    cmd()
        .arg("unset")
        .arg("-n")
        .arg("myfile")
        .arg("REMOVE_KEY")
        .arg("--force")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Get should now fail (key no longer exists)
    cmd()
        .arg("get")
        .arg("-n")
        .arg("myfile")
        .arg("REMOVE_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

// ============================================================================
// run -n tests
// ============================================================================

/// Test: `run -n myfile -- printenv KEY` outputs the value set with `set -n myfile`
#[test]
fn test_run_with_name_option() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set key in custom file
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "RUN_KEY",
        "run_secret_value",
        None,
        Some("myfile"),
    );

    // Run command that prints the env var from custom file
    #[cfg(unix)]
    {
        cmd()
            .arg("run")
            .arg("-n")
            .arg("myfile")
            .arg("--workspace")
            .arg(workspace_dir.path())
            .arg("--")
            .arg("sh")
            .arg("-c")
            .arg("echo $RUN_KEY")
            .env("SECRETENV_HOME", home_dir.path())
            .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
            .assert()
            .success()
            .stdout(predicate::str::contains("run_secret_value"));
    }
}

// ============================================================================
// failure tests
// ============================================================================

/// Test: `get -n` fails when file does not exist
#[test]
fn test_get_with_nonexistent_name_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("get")
        .arg("-n")
        .arg("nonexistent")
        .arg("SOME_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

/// Test: `-n` and default file are independent (set in one, other still empty)
#[test]
fn test_named_file_and_default_file_are_independent() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set in default file
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "DEFAULT_KEY",
        "default_value",
        None,
        None,
    );

    // Set in custom file
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "OTHER_KEY",
        "other_value",
        None,
        Some("other"),
    );

    // Default file should only have DEFAULT_KEY
    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("DEFAULT_KEY"))
        .stdout(predicate::str::contains("OTHER_KEY").not());

    // Custom file should only have OTHER_KEY
    cmd()
        .arg("list")
        .arg("-n")
        .arg("other")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("OTHER_KEY"))
        .stdout(predicate::str::contains("DEFAULT_KEY").not());
}
