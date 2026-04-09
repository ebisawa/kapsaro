// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for SSH signing method resolution
//!
//! Tests the priority order for resolving SSH signing method:
//! 1. CLI option (--ssh-agent / --ssh-keygen)
//! 2. Environment variable (SECRETENV_SSH_SIGNING_METHOD)
//! 3. Global config (SECRETENV_HOME/config.toml)
//! 4. Default (auto)

use crate::config::types::{SshSigner, SshSignerConfig};
use crate::test_utils::EnvGuard;
use serial_test::serial;
use tempfile::TempDir;

use super::{
    parse_ssh_signing_method_config, resolve_ssh_signing_method, resolve_ssh_signing_method_config,
};

#[test]
fn test_parse_ssh_signing_method_config_auto() {
    let result = parse_ssh_signing_method_config("auto").unwrap();
    assert_eq!(result, SshSignerConfig::Auto);
}

#[test]
fn test_parse_ssh_signing_method_config_ssh_agent() {
    let result = parse_ssh_signing_method_config("ssh-agent").unwrap();
    assert_eq!(result, SshSignerConfig::SshAgent);
}

#[test]
fn test_parse_ssh_signing_method_config_ssh_keygen() {
    let result = parse_ssh_signing_method_config("ssh-keygen").unwrap();
    assert_eq!(result, SshSignerConfig::SshKeygen);
}

#[test]
fn test_parse_ssh_signing_method_config_invalid() {
    let result = parse_ssh_signing_method_config("invalid");
    assert!(result.is_err());
}

#[test]
fn test_parse_ssh_signing_method_config_case_sensitive() {
    let result = parse_ssh_signing_method_config("AUTO");
    assert!(result.is_err());
}

#[test]
fn test_resolve_ssh_signing_method_config_cli_ssh_agent() {
    let result = resolve_ssh_signing_method_config(Some(SshSigner::SshAgent), None).unwrap();
    assert_eq!(result, SshSignerConfig::SshAgent);
}

#[test]
fn test_resolve_ssh_signing_method_config_cli_ssh_keygen() {
    let result = resolve_ssh_signing_method_config(Some(SshSigner::SshKeygen), None).unwrap();
    assert_eq!(result, SshSignerConfig::SshKeygen);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_config_default_is_auto() {
    let _guard = EnvGuard::new(&["SECRETENV_SSH_SIGNER", "SECRETENV_SSH_SIGNING_METHOD"]);

    let temp = TempDir::new().unwrap();
    let result = resolve_ssh_signing_method_config(None, Some(temp.path())).unwrap();

    assert_eq!(result, SshSignerConfig::Auto);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_config_env_var_auto() {
    let _guard = EnvGuard::new(&["SECRETENV_SSH_SIGNER", "SECRETENV_SSH_SIGNING_METHOD"]);
    std::env::set_var("SECRETENV_SSH_SIGNING_METHOD", "auto");

    let result = resolve_ssh_signing_method_config(None, None).unwrap();

    assert_eq!(result, SshSignerConfig::Auto);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_config_env_var_ssh_agent() {
    let _guard = EnvGuard::new(&["SECRETENV_SSH_SIGNER", "SECRETENV_SSH_SIGNING_METHOD"]);
    std::env::set_var("SECRETENV_SSH_SIGNING_METHOD", "ssh-agent");

    let result = resolve_ssh_signing_method_config(None, None).unwrap();

    assert_eq!(result, SshSignerConfig::SshAgent);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_config_env_var_ssh_keygen() {
    let _guard = EnvGuard::new(&["SECRETENV_SSH_SIGNER", "SECRETENV_SSH_SIGNING_METHOD"]);
    std::env::set_var("SECRETENV_SSH_SIGNING_METHOD", "ssh-keygen");

    let result = resolve_ssh_signing_method_config(None, None).unwrap();

    assert_eq!(result, SshSignerConfig::SshKeygen);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_config_old_env_var_is_ignored() {
    let _guard = EnvGuard::new(&["SECRETENV_SSH_SIGNER", "SECRETENV_SSH_SIGNING_METHOD"]);
    std::env::set_var("SECRETENV_SSH_SIGNER", "ssh-agent");

    let temp = TempDir::new().unwrap();
    let result = resolve_ssh_signing_method_config(None, Some(temp.path())).unwrap();

    assert_eq!(result, SshSignerConfig::Auto);
}

#[test]
fn test_resolve_ssh_signing_method_ssh_agent() {
    let result = resolve_ssh_signing_method(SshSignerConfig::SshAgent);
    assert_eq!(result, SshSigner::SshAgent);
}

#[test]
fn test_resolve_ssh_signing_method_ssh_keygen() {
    let result = resolve_ssh_signing_method(SshSignerConfig::SshKeygen);
    assert_eq!(result, SshSigner::SshKeygen);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_auto_with_agent() {
    let _guard = EnvGuard::new(&["HOME", "SSH_AUTH_SOCK"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("HOME", temp_dir.path());
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/dummy-agent.sock");

    let result = resolve_ssh_signing_method(SshSignerConfig::Auto);

    assert_eq!(result, SshSigner::SshAgent);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_auto_without_agent() {
    let _guard = EnvGuard::new(&["HOME", "SSH_AUTH_SOCK"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("HOME", temp_dir.path());
    std::env::remove_var("SSH_AUTH_SOCK");

    let result = resolve_ssh_signing_method(SshSignerConfig::Auto);

    assert_eq!(result, SshSigner::SshKeygen);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_auto_with_explicit_key_prefers_agent_when_available() {
    let _guard = EnvGuard::new(&["HOME", "SSH_AUTH_SOCK"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("HOME", temp_dir.path());
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/dummy-agent.sock");

    let result = resolve_ssh_signing_method(SshSignerConfig::Auto);

    assert_eq!(result, SshSigner::SshAgent);
}

#[test]
fn test_ssh_signing_method_display() {
    assert_eq!(format!("{}", SshSigner::SshAgent), "ssh-agent");
    assert_eq!(format!("{}", SshSigner::SshKeygen), "ssh-keygen");
}
