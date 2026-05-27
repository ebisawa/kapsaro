// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for top-level CLI help output.

use crate::cli::common::cmd;
use console::strip_ansi_codes;
use predicates::prelude::*;

#[test]
fn test_top_level_help_shows_usage() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: secretenv <COMMAND>"));
}

#[test]
fn test_top_level_help_is_not_colored_as_error_when_forced() {
    let assert = cmd()
        .arg("--help")
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stdout.contains("Usage: secretenv <COMMAND>"));
    assert!(
        !stdout.contains("\u{1b}[31m"),
        "help must not be rendered as an error: {stdout}"
    );
    assert!(stderr.is_empty(), "help stderr must be empty: {stderr}");
}

#[test]
fn test_top_level_parse_error_is_colored_when_forced() {
    let assert = cmd()
        .arg("--definitely-unknown")
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .failure()
        .code(2);

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stdout.is_empty(),
        "parse error stdout must be empty: {stdout}"
    );
    assert!(
        stderr.contains("\u{1b}[31merror: unexpected argument '--definitely-unknown' found"),
        "expected ANSI-colored clap error in stderr, got: {stderr}"
    );
    assert!(
        strip_ansi_codes(&stderr).contains("Usage: secretenv <COMMAND>"),
        "expected usage after stripping ANSI, got: {stderr}"
    );
}
