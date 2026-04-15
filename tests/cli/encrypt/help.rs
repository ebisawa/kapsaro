// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Help output tests for encrypt command

use crate::cli::common::cmd;
use predicates::prelude::*;

#[test]
fn test_encrypt_help_aligns_multiline_usage() {
    cmd()
        .arg("encrypt")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Usage: secretenv encrypt [OPTIONS] <INPUT>\n       secretenv encrypt [OPTIONS] --stdin (--out <path> | --stdout)",
        ));
}
