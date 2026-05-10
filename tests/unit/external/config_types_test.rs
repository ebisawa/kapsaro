// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for config value types.

use crate::test_utils::EnvGuard;
use secretenv::io::config::paths::get_global_config_path;
use std::path::PathBuf;

#[test]
fn test_config_xdg_path_resolution() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "HOME"]);
    std::env::set_var("SECRETENV_HOME", "/tmp/test-config");
    let path = get_global_config_path().unwrap();
    assert_eq!(path, PathBuf::from("/tmp/test-config/config.toml"));
}

#[test]
fn test_config_home_fallback() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "HOME"]);
    std::env::remove_var("SECRETENV_HOME");
    std::env::set_var("HOME", "/home/testuser");
    let path = get_global_config_path().unwrap();
    assert_eq!(
        path,
        PathBuf::from("/home/testuser/.config/secretenv/config.toml")
    );
}
