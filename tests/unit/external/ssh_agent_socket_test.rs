// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH agent socket resolution

use crate::test_utils::EnvGuard;
use secretenv::io::ssh::agent::socket::resolve_agent_socket_path;
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_resolve_agent_socket_path_from_config() {
    let _guard = EnvGuard::new(&["HOME", "SSH_AUTH_SOCK"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());
    env::remove_var("SSH_AUTH_SOCK");

    // Create .ssh/config with IdentityAgent
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

    let result = resolve_agent_socket_path();
    assert!(result.is_ok());
    let path = result.unwrap();
    assert!(path.to_string_lossy().contains("test/agent.sock"));
}

#[test]
fn test_resolve_agent_socket_path_from_env() {
    let _guard = EnvGuard::new(&["HOME", "SSH_AUTH_SOCK"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());

    // Set SSH_AUTH_SOCK (no config file)
    let sock_path = "/tmp/test-agent.sock";
    env::set_var("SSH_AUTH_SOCK", sock_path);

    let result = resolve_agent_socket_path();
    assert!(result.is_ok());
    let path = result.unwrap();
    assert_eq!(path, PathBuf::from(sock_path));
}

#[test]
fn test_resolve_agent_socket_path_config_priority() {
    let _guard = EnvGuard::new(&["HOME", "SSH_AUTH_SOCK"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());

    // Set both config and env - config should win
    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let config_path = ssh_dir.join("config");
    fs::write(
        &config_path,
        r#"Host *
    IdentityAgent "~/config/agent.sock"
"#,
    )
    .unwrap();

    env::set_var("SSH_AUTH_SOCK", "/env/agent.sock");

    let result = resolve_agent_socket_path();
    assert!(result.is_ok());
    let path = result.unwrap();
    assert!(path.to_string_lossy().contains("config/agent.sock"));
    assert!(!path.to_string_lossy().contains("/env/agent.sock"));
}

#[test]
fn test_resolve_agent_socket_path_none() {
    let _guard = EnvGuard::new(&["HOME", "SSH_AUTH_SOCK"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());
    env::remove_var("SSH_AUTH_SOCK");

    // Config with IdentityAgent none
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

    let result = resolve_agent_socket_path();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("SSH_AUTH_SOCK") || err_msg.contains("IdentityAgent"));
}

#[test]
fn test_resolve_agent_socket_path_not_found() {
    let _guard = EnvGuard::new(&["HOME", "SSH_AUTH_SOCK"]);
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();
    env::set_var("HOME", home.to_str().unwrap());
    env::remove_var("SSH_AUTH_SOCK");

    // No config file, no SSH_AUTH_SOCK

    let result = resolve_agent_socket_path();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("SSH_AUTH_SOCK"));
    assert!(err_msg.contains("IdentityAgent"));
}
