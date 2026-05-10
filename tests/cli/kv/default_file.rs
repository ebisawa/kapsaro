// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for default file path resolution

use crate::cli::common::cmd;
use predicates::prelude::*;
use tempfile::TempDir;

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
