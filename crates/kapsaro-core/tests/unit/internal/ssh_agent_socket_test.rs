// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH agent socket resolution

use crate::io::ssh::agent::socket::resolve_agent_socket_path;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_resolve_agent_socket_path_from_config() {
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();

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

    let result = resolve_agent_socket_path(Some(home), None, &BTreeMap::new());
    assert!(result.is_ok());
    let path = result.unwrap().unwrap();
    assert!(path.to_string_lossy().contains("test/agent.sock"));
}

#[test]
fn test_resolve_agent_socket_path_from_fixed_environment_value() {
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();

    // Set SSH_AUTH_SOCK (no config file)
    let sock_path = "/tmp/test-agent.sock";
    let result =
        resolve_agent_socket_path(Some(home), Some(PathBuf::from(sock_path)), &BTreeMap::new());
    assert!(result.is_ok());
    let path = result.unwrap().unwrap();
    assert_eq!(path, PathBuf::from(sock_path));
}

#[test]
fn test_resolve_agent_socket_path_from_fixed_environment_value_without_home() {
    let path = resolve_agent_socket_path(
        None,
        Some(PathBuf::from("/tmp/test-agent-without-home.sock")),
        &BTreeMap::new(),
    )
    .expect("environment socket must not require HOME")
    .unwrap();

    assert_eq!(path, PathBuf::from("/tmp/test-agent-without-home.sock"));
}

#[test]
fn test_resolve_agent_socket_path_config_priority() {
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();

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

    let result = resolve_agent_socket_path(
        Some(home),
        Some(PathBuf::from("/env/agent.sock")),
        &BTreeMap::new(),
    );
    assert!(result.is_ok());
    let path = result.unwrap().unwrap();
    assert!(path.to_string_lossy().contains("config/agent.sock"));
    assert!(!path.to_string_lossy().contains("/env/agent.sock"));
}

#[test]
fn test_resolve_agent_socket_path_none() {
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();

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

    let result = resolve_agent_socket_path(Some(home), None, &BTreeMap::new());
    assert_eq!(result.unwrap(), None);
}

#[test]
fn test_resolve_agent_socket_path_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path();

    // No config file, no SSH_AUTH_SOCK

    let result = resolve_agent_socket_path(Some(home), None, &BTreeMap::new());
    assert_eq!(result.unwrap(), None);
}
