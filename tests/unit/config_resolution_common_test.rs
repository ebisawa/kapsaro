// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::config::resolution::common::expand_tilde;
use crate::test_utils::EnvGuard;
use serial_test::serial;
use std::env;
use std::path::PathBuf;

#[test]
#[serial]
fn test_expand_tilde_with_slash() {
    let _guard = EnvGuard::new(&["HOME"]);
    env::set_var("HOME", "/home/testuser");
    let result = expand_tilde("~/.ssh/id_ed25519").unwrap();
    assert_eq!(result, PathBuf::from("/home/testuser/.ssh/id_ed25519"));
}

#[test]
#[serial]
fn test_expand_tilde_alone() {
    let _guard = EnvGuard::new(&["HOME"]);
    env::set_var("HOME", "/home/testuser");
    let result = expand_tilde("~").unwrap();
    assert_eq!(result, PathBuf::from("/home/testuser"));
}

#[test]
fn test_expand_tilde_no_tilde() {
    let result = expand_tilde("/absolute/path").unwrap();
    assert_eq!(result, PathBuf::from("/absolute/path"));
}
