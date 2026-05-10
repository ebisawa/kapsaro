// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for top-level CLI help output.

use crate::cli::common::cmd;
use predicates::prelude::*;

#[test]
fn test_top_level_help_shows_usage() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: secretenv <COMMAND>"));
}
