// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::config::resolution::common::{
    expand_tilde, resolve_ssh_add_path, resolve_ssh_keygen_path,
};
use crate::test_utils::EnvGuard;
use serial_test::serial;
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

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

#[test]
fn test_resolve_ssh_keygen_path_from_new_config_key() {
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join("config.toml");
    fs::write(
        &config_path,
        "ssh_keygen_command = \"/custom/ssh-keygen\"\n",
    )
    .unwrap();

    let result = resolve_ssh_keygen_path(Some(temp.path())).unwrap();

    assert_eq!(result, "/custom/ssh-keygen");
}

#[test]
fn test_resolve_ssh_keygen_path_ignores_old_config_key() {
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join("config.toml");
    fs::write(&config_path, "ssh_keygen = \"/custom/ssh-keygen\"\n").unwrap();

    let result = resolve_ssh_keygen_path(Some(temp.path())).unwrap();

    assert_eq!(result, "ssh-keygen");
}

#[test]
fn test_resolve_ssh_add_path_from_new_config_key() {
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join("config.toml");
    fs::write(&config_path, "ssh_add_command = \"/custom/ssh-add\"\n").unwrap();

    let result = resolve_ssh_add_path(Some(temp.path())).unwrap();

    assert_eq!(result, "/custom/ssh-add");
}

#[test]
fn test_resolve_ssh_add_path_ignores_old_config_key() {
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join("config.toml");
    fs::write(&config_path, "ssh_add = \"/custom/ssh-add\"\n").unwrap();

    let result = resolve_ssh_add_path(Some(temp.path())).unwrap();

    assert_eq!(result, "ssh-add");
}
