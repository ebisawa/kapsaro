// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for SSH OpenSSH config parsing
//!
//! These tests require file system operations and environment variable manipulation

use crate::test_utils::EnvGuard;
use secretenv_core::cli_api::test_support::storage::ssh::openssh_config::find_identity_agent;
use std::env;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_find_identity_agent_with_config_file() {
    let _guard = EnvGuard::new(&["HOME"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());

    // Create .ssh directory and config file
    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let config_path = ssh_dir.join("config");
    fs::write(
        &config_path,
        r#"Host *
    IdentityAgent "~/test/agent.sock"
"#,
    )
    .unwrap();

    let result = find_identity_agent().unwrap();
    assert!(result.is_some());
    let path = result.unwrap();
    assert!(path.to_string_lossy().contains("test/agent.sock"));
}

#[test]
fn test_find_identity_agent_no_config_file() {
    let _guard = EnvGuard::new(&["HOME"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());

    // Don't create .ssh/config

    let result = find_identity_agent().unwrap();
    assert!(result.is_none());
}

#[test]
fn test_find_identity_agent_none_value() {
    let _guard = EnvGuard::new(&["HOME"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());

    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let config_path = ssh_dir.join("config");
    fs::write(
        &config_path,
        r#"Host *
    IdentityAgent none
"#,
    )
    .unwrap();

    let result = find_identity_agent().unwrap();
    assert!(result.is_none());
}

#[test]
fn test_find_identity_agent_tilde_expansion() {
    let _guard = EnvGuard::new(&["HOME"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());

    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let config_path = ssh_dir.join("config");
    let expected_path = home
        .join("Library")
        .join("Group Containers")
        .join("test.sock");
    fs::create_dir_all(expected_path.parent().unwrap()).unwrap();

    fs::write(
        &config_path,
        r#"Host *
    IdentityAgent "~/Library/Group Containers/test.sock"
"#,
    )
    .unwrap();

    let result = find_identity_agent().unwrap();
    assert!(result.is_some());
    let path = result.unwrap();
    assert_eq!(path, expected_path);
}

#[cfg(unix)]
#[test]
fn test_find_identity_agent_rejects_symlinked_config_file() {
    use std::os::unix::fs::symlink;

    let _guard = EnvGuard::new(&["HOME"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());

    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let real_config = home.join("real_config");
    fs::write(
        &real_config,
        r#"Host *
    IdentityAgent "~/test/agent.sock"
"#,
    )
    .unwrap();
    symlink(&real_config, ssh_dir.join("config")).unwrap();

    let result = find_identity_agent();
    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(message.contains("symlink"), "unexpected error: {message}");
}

#[test]
fn test_find_identity_agent_rejects_oversized_config_file() {
    let _guard = EnvGuard::new(&["HOME"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());

    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let config_path = ssh_dir.join("config");
    fs::write(
        &config_path,
        format!(
            "Host *\n    IdentityAgent \"~/test/agent.sock\"\n#{}\n",
            "a".repeat(2 * 1024 * 1024)
        ),
    )
    .unwrap();

    let result = find_identity_agent();
    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("maximum size limit"),
        "unexpected error: {message}"
    );
}
