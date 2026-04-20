// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for default file path resolution

use crate::cli::common::{cmd, setup_workspace};
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_default_file_path_resolution() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Verify default file path
    let default_file = workspace_dir.path().join("secrets").join("default.kvenc");
    assert!(
        !default_file.exists(),
        "Default file should not exist initially"
    );

    // Create a key-value pair (this should create the default file)
    cmd()
        .arg("set")
        .arg("TEST_KEY")
        .arg("test_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify default file was created
    assert!(
        default_file.exists(),
        "Default file should be created after set command"
    );
}

#[test]
fn test_error_when_workspace_not_found() {
    let home_dir = TempDir::new().unwrap();

    // Try to run get without workspace
    cmd()
        .arg("get")
        .arg("TEST_KEY")
        .env("SECRETENV_HOME", home_dir.path())
        .current_dir("/tmp") // Ensure we're not in a workspace
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("SSH key")
                .or(predicate::str::contains("workspace"))
                .or(predicate::str::contains("member handle not configured")),
        );
}
