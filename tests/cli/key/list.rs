// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key list` command

use crate::cli::common::{cmd, generate_temp_ssh_keypair, make_secret_home, TEST_MEMBER_HANDLE};
use crate::cli::key::find_kid_in_member_dir;
use kapsaro_core::test_support::helpers::kid::format_kid_display;

#[cfg(unix)]
use std::os::unix::fs::symlink;
#[cfg(unix)]
use std::path::PathBuf;

/// Place a key under `real_home` and return a symlink standing in for it.
#[cfg(unix)]
fn linked_home_holding_one_key(temp: &tempfile::TempDir, ssh_priv: &std::path::Path) -> PathBuf {
    let real_home = temp.path().join("real-home");
    let selected_home = temp.path().join("selected-home");
    std::fs::create_dir(&real_home).unwrap();
    symlink(&real_home, &selected_home).unwrap();
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("-i")
        .arg(ssh_priv)
        .env("KAPSARO_HOME", &real_home)
        .assert()
        .success();
    selected_home
}

/// Selecting a local state root through a symlink is a supported setup, so the
/// keys behind the link are listed.
#[cfg(unix)]
#[test]
fn test_key_list_reads_through_an_explicit_home_symlink() {
    let temp = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let selected_home = linked_home_holding_one_key(&temp, &ssh_priv);

    cmd()
        .arg("key")
        .arg("list")
        .arg("--home")
        .arg(&selected_home)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .success()
        .stdout(predicates::str::contains(TEST_MEMBER_HANDLE));

    drop(ssh_temp);
}

#[cfg(unix)]
#[test]
fn test_key_list_reads_through_an_environment_home_symlink() {
    let temp = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let selected_home = linked_home_holding_one_key(&temp, &ssh_priv);

    cmd()
        .arg("key")
        .arg("list")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("KAPSARO_HOME", &selected_home)
        .assert()
        .success()
        .stdout(predicates::str::contains(TEST_MEMBER_HANDLE));

    drop(ssh_temp);
}

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
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Run key list
    let output = cmd()
        .arg("key")
        .arg("list")
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
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
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Run key list --json
    let output = cmd()
        .arg("key")
        .arg("list")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--json")
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Parse as JSON
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let keys = json["keys"].as_array().expect("keys should be an array");
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
    assert!(first_key.get("status").is_none());
    assert!(first_key.get("missing_document").is_none());
    // A freshly generated key records when it was created, and the field is a
    // timestamp rather than null so a consumer can read it without a guard.
    assert!(
        first_key["created_at"].is_string(),
        "created_at should be a timestamp, got: {}",
        first_key["created_at"]
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_list_text_shows_an_incomplete_active_key() {
    let home = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    cmd()
        .args(["key", "new", "--member-handle", TEST_MEMBER_HANDLE])
        .arg("--ssh-identity")
        .arg(&ssh_priv)
        .env("KAPSARO_HOME", home.path())
        .assert()
        .success();
    let member_dir = home.path().join("keys").join(TEST_MEMBER_HANDLE);
    let kid = find_kid_in_member_dir(&member_dir);
    std::fs::remove_file(member_dir.join(&kid).join("public.json")).unwrap();

    let output = cmd()
        .args(["key", "list", "--member-handle", TEST_MEMBER_HANDLE])
        .env("KAPSARO_HOME", home.path())
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    assert!(
        stdout.contains(&format_kid_display(&kid).unwrap()),
        "{stdout}"
    );
    assert!(stdout.contains("ACTIVE"), "{stdout}");
    assert!(
        stdout.contains("Incomplete (missing public.json)"),
        "{stdout}"
    );
    assert!(stdout.contains("Total: 1 key(s)"), "{stdout}");
    drop(ssh_temp);
}

#[test]
fn test_key_list_json_shows_an_incomplete_active_key() {
    let home = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    cmd()
        .args(["key", "new", "--member-handle", TEST_MEMBER_HANDLE])
        .arg("--ssh-identity")
        .arg(&ssh_priv)
        .env("KAPSARO_HOME", home.path())
        .assert()
        .success();
    let member_dir = home.path().join("keys").join(TEST_MEMBER_HANDLE);
    let kid = find_kid_in_member_dir(&member_dir);
    std::fs::remove_file(member_dir.join(&kid).join("public.json")).unwrap();

    let output = cmd()
        .args([
            "key",
            "list",
            "--member-handle",
            TEST_MEMBER_HANDLE,
            "--json",
        ])
        .env("KAPSARO_HOME", home.path())
        .assert()
        .success();
    let document: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("valid JSON output");
    let key = &document["keys"][0];

    assert_eq!(document["keys"].as_array().unwrap().len(), 1);
    assert_eq!(key["kid"], kid);
    assert_eq!(key["member_handle"], TEST_MEMBER_HANDLE);
    assert_eq!(key["active"], true);
    assert_eq!(key["status"], "incomplete");
    assert_eq!(key["missing_document"], "public.json");
    assert!(key["created_at"].is_null());
    assert!(key["expires_at"].is_null());
    assert!(key["format"].is_null());
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
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    let output = cmd()
        .arg("key")
        .arg("list")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--verbose")
        .env("KAPSARO_HOME", temp_dir.path())
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

/// A home with no keystore holds no keys, which is an answer rather than a
/// failure. It reads the same as a keystore holding no members, and the step
/// that creates a key is named on stderr.
#[test]
fn test_key_list_without_a_keystore_lists_nothing_and_names_the_next_step() {
    let temp_dir = make_secret_home();

    cmd()
        .arg("key")
        .arg("list")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("No members found in keystore"))
        .stderr(predicates::str::contains(
            "No keys found. Run 'kapsaro key new' to generate a key.",
        ));
}

#[test]
fn test_key_list_auto_resolve_member_handle() {
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
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Run key list without --member-handle (should auto-resolve)
    let output = cmd()
        .arg("key")
        .arg("list")
        .env("KAPSARO_HOME", temp_dir.path())
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
