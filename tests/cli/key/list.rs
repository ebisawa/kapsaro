// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key list` command

use crate::cli::common::{cmd, generate_temp_ssh_keypair, make_secret_home, TEST_MEMBER_HANDLE};
use tempfile::TempDir;

#[test]
fn test_key_list_basic() {
    let temp_dir = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Generate 2 keys
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Run key list
    let output = cmd()
        .arg("key")
        .arg("list")
        .arg("--member-handle")
        .arg(member_handle)
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Verify output contains member_handle
    assert!(
        stdout.contains(member_handle),
        "Output should contain member_handle"
    );

    // Verify output contains "active" marker (one key should be active)
    assert!(
        stdout.contains("active") || stdout.contains("ACTIVE") || stdout.contains("*"),
        "Output should mark the active key"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_list_json_output() {
    let temp_dir = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Generate a key
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Run key list --json
    let output = cmd()
        .arg("key")
        .arg("list")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--json")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Parse as JSON
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    // Verify structure
    assert!(
        json.is_array() || json.is_object(),
        "JSON output should be array or object"
    );

    // If array, verify first item has expected fields
    if let Some(keys) = json.as_array() {
        assert!(!keys.is_empty(), "Should have at least one key");
        let first_key = &keys[0];
        assert!(first_key.get("kid").is_some(), "Should have kid field");
        assert!(
            first_key.get("expires_at").is_some(),
            "Should have expires_at field"
        );
        assert!(
            first_key.get("member_handle").is_some(),
            "Should have member_handle field"
        );
    }

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_list_verbose_aligns_field_values() {
    let temp_dir = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let output = cmd()
        .arg("key")
        .arg("list")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--verbose")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    for prefix in [
        "  Kid:           ",
        "  Format:        ",
        "  Member Handle: ",
        "  Created:       ",
        "  Expires:       ",
    ] {
        assert!(
            stdout.lines().any(|line| line.starts_with(prefix)),
            "expected verbose key list output to contain aligned field prefix '{prefix}', got:\n{stdout}"
        );
    }

    drop(ssh_temp);
}

#[test]
fn test_key_list_empty() {
    let temp_dir = make_secret_home();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key list on empty keystore
    let output = cmd()
        .arg("key")
        .arg("list")
        .arg("--member-handle")
        .arg(member_handle)
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Verify output indicates no keys (should not panic)
    assert!(
        stdout.contains("No members")
            || stdout.contains("No keys")
            || stdout.is_empty()
            || stdout.contains("0 key")
            || stdout.contains("Total: 0"),
        "Output should indicate no keys found, got: '{}'",
        stdout
    );
}

#[test]
fn test_key_list_auto_resolve_member_handle() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Generate a key
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Run key list without --member-handle (should auto-resolve)
    let output = cmd()
        .arg("key")
        .arg("list")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Verify output contains the member_handle
    assert!(
        stdout.contains(member_handle),
        "Output should contain auto-resolved member_handle"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}
