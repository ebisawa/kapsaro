// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for member list/show/remove/add commands

use crate::cli::common::{cmd, setup_workspace, ALICE_MEMBER_ID, BOB_MEMBER_ID, TEST_MEMBER_ID};
use crate::test_utils::{
    save_active_public_key_to_workspace, setup_member_key_context, setup_test_workspace,
    setup_trust_store_for_workspace, update_active_private_key_expires_at,
};
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn save_tampered_member_file(member_file: &std::path::Path, tamper: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_str(&fs::read_to_string(member_file).unwrap()).unwrap();
    tamper(&mut value);
    fs::write(member_file, serde_json::to_string_pretty(&value).unwrap()).unwrap();
}

fn copy_fresh_public_key(temp_key_file: &std::path::Path) {
    let (other_workspace_dir, _other_home_dir, _other_ssh_temp, _other_ssh_priv) =
        setup_workspace();
    let other_active_key_path = other_workspace_dir
        .path()
        .join("members")
        .join("active")
        .join(format!("{}.json", TEST_MEMBER_ID));
    fs::copy(other_active_key_path, temp_key_file).unwrap();
}

fn fixture_ssh_key_path(temp_dir: &TempDir) -> std::path::PathBuf {
    temp_dir.path().join(".ssh").join("test_ed25519")
}

// ============================================================================
// member list
// ============================================================================

#[test]
fn test_member_list_shows_initialized_member() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(TEST_MEMBER_ID));
}

#[test]
fn test_member_list_json_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let assert = cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--json")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("member list --json should output valid JSON");

    assert!(
        parsed.get("active").is_some(),
        "JSON should have 'active' key"
    );
    let active = parsed["active"]
        .as_array()
        .expect("active should be an array");
    assert!(
        !active.is_empty(),
        "active array should contain the initialized member"
    );
}

#[test]
fn test_member_list_empty_workspace() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();

    // Create workspace directory structure without running init
    // Workspace validation requires members/active/ subdirectory
    fs::create_dir_all(workspace_dir.path().join("members").join("active")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("No members found"));
}

#[test]
fn test_member_list_json_skips_invalid_member_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let incoming_dir = workspace_dir.path().join("members").join("incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    let incoming_file = incoming_dir.join("broken@example.com.json");
    let active_key_path = workspace_dir
        .path()
        .join("members")
        .join("active")
        .join(format!("{}.json", TEST_MEMBER_ID));
    fs::copy(&active_key_path, &incoming_file).unwrap();
    save_tampered_member_file(&incoming_file, |value| {
        value["protected"]["expires_at"] = Value::String("2030-01-01T00:00:00Z".to_string());
    });

    let assert = cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--json")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let incoming = parsed["incoming"].as_array().unwrap();
    assert!(incoming.is_empty());

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("Skipping invalid member file"));
}

// ============================================================================
// member show
// ============================================================================

#[test]
fn test_member_show_displays_public_key() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("member")
        .arg("show")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "\u{25CF} {}",
            TEST_MEMBER_ID
        )))
        .stdout(predicate::str::contains("\nStatus\n"))
        .stdout(predicate::str::contains("  Membership  :"))
        .stdout(predicate::str::contains("  Verification:"))
        .stdout(predicate::str::contains("\nKey  "))
        .stdout(predicate::str::contains("  Algorithm   :"))
        .stdout(predicate::str::contains("\nSSH Attestation\n"))
        .stdout(predicate::str::contains("  Fingerprint : SHA256:"))
        .stdout(predicate::str::contains("\nIdentity\n").not())
        .stdout(predicate::str::contains("Public Key").not());
}

#[test]
fn test_member_show_reports_verification_warning() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[TEST_MEMBER_ID]);
    update_active_private_key_expires_at(temp_dir.path(), TEST_MEMBER_ID, "2020-01-01T00:00:00Z");
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, TEST_MEMBER_ID).unwrap();

    cmd()
        .arg("member")
        .arg("show")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_IDENTITY", fixture_ssh_key_path(&temp_dir))
        .assert()
        .success()
        .stdout(predicate::str::contains("Verification: expired"))
        .stderr(predicate::str::contains("has expired"));
}

#[test]
fn test_member_show_unknown_member_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("member")
        .arg("show")
        .arg("nonexistent@example.com")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_member_show_invalid_member_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let member_file = workspace_dir
        .path()
        .join("members")
        .join("active")
        .join(format!("{}.json", TEST_MEMBER_ID));
    save_tampered_member_file(&member_file, |value| {
        value["protected"]["identity"]["attestation"]["sig"] = Value::String("broken".to_string());
    });

    cmd()
        .arg("member")
        .arg("show")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_member_verify_approve_requires_manual_confirmation_non_interactive() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);

    cmd()
        .arg("member")
        .arg("verify")
        .arg("--approve")
        .arg(BOB_MEMBER_ID)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_MEMBER_HANDLE", ALICE_MEMBER_ID)
        .env("SECRETENV_SSH_IDENTITY", fixture_ssh_key_path(&temp_dir))
        .assert()
        .failure()
        .stderr(predicate::str::contains("interactive confirmation"));
}

#[test]
fn test_member_verify_approve_accepts_member_id_option_for_trust_store_owner() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    fs::remove_file(temp_dir.path().join("config.toml")).unwrap();

    cmd()
        .arg("member")
        .arg("verify")
        .arg("--approve")
        .arg(BOB_MEMBER_ID)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("SECRETENV_HOME", temp_dir.path().to_str().unwrap())
        .env_remove("SECRETENV_MEMBER_HANDLE")
        .env("SECRETENV_SSH_IDENTITY", fixture_ssh_key_path(&temp_dir))
        .assert()
        .failure()
        .stderr(predicate::str::contains("Specify --member-handle"));

    cmd()
        .arg("member")
        .arg("verify")
        .arg("--approve")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
        .arg(BOB_MEMBER_ID)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("SECRETENV_HOME", temp_dir.path().to_str().unwrap())
        .env_remove("SECRETENV_MEMBER_HANDLE")
        .env("SECRETENV_SSH_IDENTITY", fixture_ssh_key_path(&temp_dir))
        .assert()
        .failure()
        .stderr(predicate::str::contains("interactive confirmation"))
        .stderr(predicate::str::contains("Specify --member-handle").not());
}

#[test]
fn test_member_verify_approve_hides_already_known_results() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    cmd()
        .arg("member")
        .arg("verify")
        .arg("--approve")
        .arg(BOB_MEMBER_ID)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_MEMBER_HANDLE", ALICE_MEMBER_ID)
        .env("SECRETENV_SSH_IDENTITY", fixture_ssh_key_path(&temp_dir))
        .assert()
        .success()
        .stderr(predicate::str::contains("No members require approval"))
        .stderr(predicate::str::contains(BOB_MEMBER_ID).not())
        .stderr(predicate::str::contains("already known").not())
        .stderr(predicate::str::contains("Approved ").not());
}

#[test]
fn test_member_verify_approve_json_skips_already_known_results() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let assert = cmd()
        .arg("member")
        .arg("verify")
        .arg("--approve")
        .arg(BOB_MEMBER_ID)
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--json")
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_MEMBER_HANDLE", ALICE_MEMBER_ID)
        .env("SECRETENV_SSH_IDENTITY", fixture_ssh_key_path(&temp_dir))
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let json_start = stdout
        .find('{')
        .expect("member verify --approve --json should include JSON object");
    let parsed: serde_json::Value = serde_json::from_str(&stdout[json_start..])
        .expect("member verify --approve --json should output JSON");

    assert_eq!(parsed["results"], serde_json::json!([]));

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        !stderr.contains(BOB_MEMBER_ID),
        "unexpected stderr: {}",
        stderr
    );
}

// ============================================================================
// member remove
// ============================================================================

#[test]
fn test_member_remove_removes_from_workspace() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Confirm the member exists before removal
    cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(TEST_MEMBER_ID));

    // Remove the member with --force
    cmd()
        .arg("member")
        .arg("remove")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--force")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify the member no longer appears in the active list
    let assert = cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    // After removing the only member, the list should show no members or not list
    // the removed member under Active
    assert!(
        !stdout.contains(&format!("  {}", TEST_MEMBER_ID)) || stdout.contains("No members found"),
        "Removed member should not appear in active member list, got: {}",
        stdout
    );
}

#[test]
fn test_member_remove_without_force_in_non_interactive_mode_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("member")
        .arg("remove")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "without --force in non-interactive mode",
        ));

    cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(TEST_MEMBER_ID));
}

#[test]
fn test_member_remove_nonexistent_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("member")
        .arg("remove")
        .arg("nonexistent@example.com")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--force")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_member_remove_warns_on_tampered_artifact_but_continues() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let input_file = home_dir.path().join("member-remove.txt");
    let encrypted_file = workspace_dir
        .path()
        .join("secrets")
        .join("member-remove.json");
    fs::write(&input_file, b"member remove preview").unwrap();

    cmd()
        .arg("encrypt")
        .arg(&input_file)
        .arg("--out")
        .arg(&encrypted_file)
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let mut value: Value =
        serde_json::from_str(&fs::read_to_string(&encrypted_file).unwrap()).unwrap();
    value["protected"]["updated_at"] = Value::String("2026-01-01T00:00:01Z".to_string());
    fs::write(
        &encrypted_file,
        serde_json::to_string_pretty(&value).unwrap(),
    )
    .unwrap();

    cmd()
        .arg("member")
        .arg("remove")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--force")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("member-remove.json"))
        .stderr(predicate::str::contains("Signature verification failed"));
}

// ============================================================================
// member add
// ============================================================================

#[test]
fn test_member_add_places_in_incoming() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let temp_dir = TempDir::new().unwrap();
    let temp_key_file = temp_dir.path().join("pubkey.json");
    copy_fresh_public_key(&temp_key_file);

    cmd()
        .arg("member")
        .arg("add")
        .arg(&temp_key_file)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Added member"));
}

#[test]
fn test_member_add_invalid_file_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let temp_dir = TempDir::new().unwrap();
    let temp_key_file = temp_dir.path().join("invalid.json");
    fs::write(&temp_key_file, "not json").unwrap();

    cmd()
        .arg("member")
        .arg("add")
        .arg(&temp_key_file)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_member_add_duplicate_without_force_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let temp_dir = TempDir::new().unwrap();
    let temp_key_file = temp_dir.path().join("pubkey.json");
    copy_fresh_public_key(&temp_key_file);

    // First add succeeds
    cmd()
        .arg("member")
        .arg("add")
        .arg(&temp_key_file)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Second add without --force fails
    cmd()
        .arg("member")
        .arg("add")
        .arg(&temp_key_file)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_member_verify_reports_offline_invalid_member() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let incoming_dir = workspace_dir.path().join("members").join("incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    let incoming_file = incoming_dir.join("broken@example.com.json");
    let active_key_path = workspace_dir
        .path()
        .join("members")
        .join("active")
        .join(format!("{}.json", TEST_MEMBER_ID));
    fs::copy(&active_key_path, &incoming_file).unwrap();
    save_tampered_member_file(&incoming_file, |value| {
        value["protected"]["identity"]["attestation"]["sig"] = Value::String("broken".to_string());
    });

    cmd()
        .arg("member")
        .arg("verify")
        .arg("broken@example.com")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found in active/"));
}

#[test]
fn test_member_verify_ignores_invalid_incoming_member_when_verifying_all() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let incoming_dir = workspace_dir.path().join("members").join("incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    let incoming_file = incoming_dir.join("broken@example.com.json");
    let active_key_path = workspace_dir
        .path()
        .join("members")
        .join("active")
        .join(format!("{}.json", TEST_MEMBER_ID));
    fs::copy(&active_key_path, &incoming_file).unwrap();
    save_tampered_member_file(&incoming_file, |value| {
        value["protected"]["identity"]["attestation"]["sig"] = Value::String("broken".to_string());
    });

    let assert = cmd()
        .arg("member")
        .arg("verify")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--json")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let results = parsed["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["member_id"], TEST_MEMBER_ID);
}
