// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for io/config/store module
//!
//! Tests for load_config_file, set_config_value, and unset_config_value functions.

use secretenv::io::config::store::{load_config_file, set_config_value, unset_config_value};
use secretenv::support::limits::MAX_CONFIG_FILE_SIZE;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// load_config_file tests
// ---------------------------------------------------------------------------

#[test]
fn test_load_config_file_nonexistent() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("nonexistent.toml");

    let result = load_config_file(&path, tmp.path()).unwrap();
    assert!(
        result.is_empty(),
        "nonexistent file should return empty map"
    );
}

#[test]
fn test_load_config_file_empty() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("empty.toml");
    fs::write(&path, "").unwrap();

    let result = load_config_file(&path, tmp.path()).unwrap();
    assert!(result.is_empty(), "empty file should return empty map");
}

#[test]
fn test_load_config_file_valid() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    fs::write(
        &path,
        r#"
member_handle = "alice@example.com"
ssh_signing_method = "ssh-agent"
ssh_keygen_command = "/usr/bin/ssh-keygen"
ssh_add_command = "/usr/bin/ssh-add"
"#,
    )
    .unwrap();

    let result = load_config_file(&path, tmp.path()).unwrap();
    assert_eq!(result.len(), 4);
    assert_eq!(result.get("member_handle").unwrap(), "alice@example.com");
    assert_eq!(result.get("ssh_signing_method").unwrap(), "ssh-agent");
    assert_eq!(
        result.get("ssh_keygen_command").unwrap(),
        "/usr/bin/ssh-keygen"
    );
    assert_eq!(result.get("ssh_add_command").unwrap(), "/usr/bin/ssh-add");
}

#[cfg(unix)]
#[test]
fn test_load_config_file_rejects_symlinked_config_file() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("target.toml");
    let path = tmp.path().join("config.toml");
    fs::write(&target, "member_handle = \"alice@example.com\"\n").unwrap();
    symlink(&target, &path).unwrap();

    let error = load_config_file(&path, tmp.path()).unwrap_err();

    assert!(error.to_string().contains("symlink"));
}

#[test]
fn test_load_config_file_invalid_toml() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("bad.toml");
    fs::write(&path, "this is not valid = toml [[[").unwrap();

    let result = load_config_file(&path, tmp.path());
    assert!(result.is_err(), "invalid TOML should return an error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Invalid TOML"),
        "error should mention invalid TOML, got: {}",
        err_msg
    );
}

#[test]
fn test_load_config_file_rejects_oversized_file() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    fs::write(&path, "a".repeat(MAX_CONFIG_FILE_SIZE + 1)).unwrap();

    let error = load_config_file(&path, tmp.path()).unwrap_err();

    assert!(error.to_string().contains("maximum size limit"));
}

#[test]
fn test_load_config_file_ignores_non_string_values() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("mixed.toml");
    fs::write(
        &path,
        r#"
string_key = "hello"
int_key = 42
bool_key = true
float_key = 3.14
"#,
    )
    .unwrap();

    let result = load_config_file(&path, tmp.path()).unwrap();
    assert_eq!(result.len(), 1, "only string values should be included");
    assert_eq!(result.get("string_key").unwrap(), "hello");
    assert!(!result.contains_key("int_key"));
    assert!(!result.contains_key("bool_key"));
    assert!(!result.contains_key("float_key"));
}

// ---------------------------------------------------------------------------
// set_config_value tests
// ---------------------------------------------------------------------------

#[test]
fn test_set_config_value_new_file() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("new_config.toml");

    set_config_value(&path, "member_handle", "bob@example.com").unwrap();

    let config = load_config_file(&path, tmp.path()).unwrap();
    assert_eq!(config.get("member_handle").unwrap(), "bob@example.com");
}

#[test]
fn test_set_config_value_update_existing() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    fs::write(&path, "member_handle = \"old@example.com\"\n").unwrap();

    set_config_value(&path, "member_handle", "new@example.com").unwrap();

    let config = load_config_file(&path, tmp.path()).unwrap();
    assert_eq!(config.get("member_handle").unwrap(), "new@example.com");
}

#[cfg(unix)]
#[test]
fn test_set_config_value_rejects_symlinked_lock_file() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    let victim = tmp.path().join("victim.txt");
    fs::write(&victim, "original").unwrap();
    symlink(&victim, tmp.path().join(".config.toml.lock")).unwrap();

    let error = set_config_value(&path, "member_handle", "alice@example.com").unwrap_err();

    assert!(error.to_string().contains("symlink"));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "original");
}

// ---------------------------------------------------------------------------
// unset_config_value tests
// ---------------------------------------------------------------------------

#[test]
fn test_unset_config_value() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    fs::write(
        &path,
        "member_handle = \"alice@example.com\"\nssh_signing_method = \"ssh-agent\"\n",
    )
    .unwrap();

    unset_config_value(&path, "member_handle").unwrap();

    let config = load_config_file(&path, tmp.path()).unwrap();
    assert!(
        !config.contains_key("member_handle"),
        "member_handle should be removed"
    );
    assert_eq!(
        config.get("ssh_signing_method").unwrap(),
        "ssh-agent",
        "other keys should remain"
    );
}

#[test]
fn test_unset_config_value_not_found() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    fs::write(&path, "member_handle = \"alice@example.com\"\n").unwrap();

    let result = unset_config_value(&path, "nonexistent_key");
    assert!(result.is_err(), "removing nonexistent key should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not found"),
        "error should mention key not found, got: {}",
        err_msg
    );
}

#[cfg(unix)]
#[test]
fn test_load_config_file_warns_on_insecure_parent_directory_permissions() {
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path().join("secretenv");
    let path = base_dir.join("config.toml");
    fs::create_dir_all(&base_dir).unwrap();
    fs::write(&path, "member_handle = \"alice@example.com\"\n").unwrap();
    fs::set_permissions(&base_dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let result = load_config_file(&path, &base_dir).unwrap();

    assert_eq!(result.get("member_handle").unwrap(), "alice@example.com");
}
