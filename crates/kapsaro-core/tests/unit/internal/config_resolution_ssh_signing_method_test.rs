// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for SSH signing method resolution
//!
//! Tests the priority order for resolving SSH signing method:
//! 1. CLI option (--ssh-agent / --ssh-keygen)
//! 2. Environment variable (KAPSARO_SSH_SIGNING_METHOD)
//! 3. Global config (KAPSARO_HOME/config.toml)
//! 4. Default (auto)

use crate::config::types::{SshSigningMethod, SshSigningMethodConfig};
use crate::test_utils::EnvGuard;
use serial_test::serial;
use tempfile::TempDir;

use super::{
    parse_ssh_signing_method_config, resolve_ssh_signing_method, resolve_ssh_signing_method_config,
};

#[test]
fn test_parse_ssh_signing_method_config_auto() {
    let result = parse_ssh_signing_method_config("auto").unwrap();
    assert_eq!(result, SshSigningMethodConfig::Auto);
}

#[test]
fn test_parse_ssh_signing_method_config_ssh_agent() {
    let result = parse_ssh_signing_method_config("ssh-agent").unwrap();
    assert_eq!(result, SshSigningMethodConfig::SshAgent);
}

#[test]
fn test_parse_ssh_signing_method_config_ssh_keygen() {
    let result = parse_ssh_signing_method_config("ssh-keygen").unwrap();
    assert_eq!(result, SshSigningMethodConfig::SshKeygen);
}

#[test]
fn test_parse_ssh_signing_method_config_invalid() {
    let result = parse_ssh_signing_method_config("invalid");
    assert!(result.is_err());
}

#[test]
fn test_resolve_ssh_signing_method_config_cli_ssh_agent() {
    let result = resolve_ssh_signing_method_config(Some(SshSigningMethod::SshAgent), None).unwrap();
    assert_eq!(result, SshSigningMethodConfig::SshAgent);
}

#[test]
fn test_resolve_ssh_signing_method_config_cli_ssh_keygen() {
    let result =
        resolve_ssh_signing_method_config(Some(SshSigningMethod::SshKeygen), None).unwrap();
    assert_eq!(result, SshSigningMethodConfig::SshKeygen);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_config_default_is_auto() {
    let _guard = EnvGuard::new(&["KAPSARO_SSH_SIGNER", "KAPSARO_SSH_SIGNING_METHOD"]);

    let temp = TempDir::new().unwrap();
    let result = resolve_ssh_signing_method_config(None, Some(temp.path())).unwrap();

    assert_eq!(result, SshSigningMethodConfig::Auto);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_config_env_var_ssh_agent() {
    let _guard = EnvGuard::new(&["KAPSARO_SSH_SIGNER", "KAPSARO_SSH_SIGNING_METHOD"]);
    std::env::set_var("KAPSARO_SSH_SIGNING_METHOD", "ssh-agent");

    let result = resolve_ssh_signing_method_config(None, None).unwrap();

    assert_eq!(result, SshSigningMethodConfig::SshAgent);
}

#[test]
fn test_resolve_ssh_signing_method_ssh_agent() {
    let result = resolve_ssh_signing_method(SshSigningMethodConfig::SshAgent);
    assert_eq!(result, SshSigningMethod::SshAgent);
}

#[test]
fn test_resolve_ssh_signing_method_ssh_keygen() {
    let result = resolve_ssh_signing_method(SshSigningMethodConfig::SshKeygen);
    assert_eq!(result, SshSigningMethod::SshKeygen);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_auto_with_agent() {
    let _guard = EnvGuard::new(&["HOME", "SSH_AUTH_SOCK"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("HOME", temp_dir.path());
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/dummy-agent.sock");

    let result = resolve_ssh_signing_method(SshSigningMethodConfig::Auto);

    assert_eq!(result, SshSigningMethod::SshAgent);
}

#[test]
#[serial]
fn test_resolve_ssh_signing_method_auto_without_agent() {
    let _guard = EnvGuard::new(&["HOME", "SSH_AUTH_SOCK"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("HOME", temp_dir.path());
    std::env::remove_var("SSH_AUTH_SOCK");

    let result = resolve_ssh_signing_method(SshSigningMethodConfig::Auto);

    assert_eq!(result, SshSigningMethod::SshKeygen);
}

#[test]
fn test_ssh_signing_method_display() {
    assert_eq!(format!("{}", SshSigningMethod::SshAgent), "ssh-agent");
    assert_eq!(format!("{}", SshSigningMethod::SshKeygen), "ssh-keygen");
}
