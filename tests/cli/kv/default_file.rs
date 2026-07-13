// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for default file path resolution

use crate::cli::common::cmd;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_error_when_workspace_not_found() {
    let home_dir = TempDir::new().unwrap();
    let current_dir = TempDir::new().unwrap();

    // Try to run get without workspace.
    cmd()
        .arg("get")
        .arg("--all")
        .env("KAPSARO_HOME", home_dir.path())
        .env_remove("KAPSARO_MEMBER_HANDLE")
        .env_remove("KAPSARO_WORKSPACE")
        .env_remove("KAPSARO_PRIVATE_KEY")
        .current_dir(current_dir.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Error: workspace not found.\nReason:")
                .and(predicate::str::contains("kapsaro init"))
                .and(predicate::str::contains("\nOptions:\n1."))
                .and(predicate::str::contains("--workspace <path>"))
                .and(predicate::str::contains("member handle not configured").not()),
        );
}
