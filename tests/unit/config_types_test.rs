// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for config module (Phase 10.1 - TDD Red phase)

use crate::test_utils::EnvGuard;
use secretenv::config::types::{ConfigDocument, SshConfig, SshSigningMethodConfig};
use secretenv::io::config::paths::get_global_config_path;
use std::path::PathBuf;

#[test]
fn test_default_config() {
    let config = SshConfig::default();
    assert_eq!(config.ssh_add_path, "ssh-add");
    assert_eq!(config.ssh_keygen_path, "ssh-keygen");
    assert!(matches!(
        config.signing_method,
        SshSigningMethodConfig::Auto
    ));
}

#[test]
fn test_config_deserialize_minimal() {
    let toml = r#"format = "secretenv/config@1""#;
    let doc: ConfigDocument = toml::from_str(toml).unwrap();
    assert_eq!(doc.format, "secretenv/config@1");
    assert!(matches!(
        doc.ssh.signing_method,
        SshSigningMethodConfig::Auto
    ));
}

#[test]
fn test_config_deserialize_full() {
    let toml = r#"
format = "secretenv/config@1"

[ssh]
ssh_add_path = "/usr/bin/ssh-add"
ssh_keygen_path = "/usr/bin/ssh-keygen"
ssh_signing_method = "ssh-agent"
"#;
    let doc: ConfigDocument = toml::from_str(toml).unwrap();
    assert_eq!(doc.ssh.ssh_add_path, "/usr/bin/ssh-add");
    assert!(matches!(
        doc.ssh.signing_method,
        SshSigningMethodConfig::SshAgent
    ));
}

#[test]
fn test_config_invalid_format() {
    let toml = r#"format = "secretenv/config@999""#;
    let doc: ConfigDocument = toml::from_str(toml).unwrap();
    // load_config() should reject this format later
    assert_eq!(doc.format, "secretenv/config@999");
}

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

#[test]
fn test_signing_method_config_serialization() {
    let auto = SshSigningMethodConfig::Auto;
    let ssh_agent = SshSigningMethodConfig::SshAgent;
    let ssh_keygen = SshSigningMethodConfig::SshKeygen;

    assert_eq!(serde_json::to_string(&auto).unwrap(), r#""auto""#);
    assert_eq!(serde_json::to_string(&ssh_agent).unwrap(), r#""ssh-agent""#);
    assert_eq!(
        serde_json::to_string(&ssh_keygen).unwrap(),
        r#""ssh-keygen""#
    );
}

#[test]
fn test_signing_method_config_deserialization() {
    let auto: SshSigningMethodConfig = serde_json::from_str(r#""auto""#).unwrap();
    let agent: SshSigningMethodConfig = serde_json::from_str(r#""ssh-agent""#).unwrap();
    let keygen: SshSigningMethodConfig = serde_json::from_str(r#""ssh-keygen""#).unwrap();

    assert!(matches!(auto, SshSigningMethodConfig::Auto));
    assert!(matches!(agent, SshSigningMethodConfig::SshAgent));
    assert!(matches!(keygen, SshSigningMethodConfig::SshKeygen));
}

#[test]
fn test_config_deserialize_auto() {
    let toml = r#"
format = "secretenv/config@1"

[ssh]
ssh_signing_method = "auto"
"#;
    let doc: ConfigDocument = toml::from_str(toml).unwrap();
    assert!(matches!(
        doc.ssh.signing_method,
        SshSigningMethodConfig::Auto
    ));
}
