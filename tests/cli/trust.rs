// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for trust commands.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::cli::common::{cmd, ALICE_MEMBER_ID};
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use assert_cmd::cargo;
use predicates::prelude::*;
use secretenv::feature::trust::signature::sign_trust_store;
use secretenv::io::trust::paths::trust_store_file_path;
use secretenv::io::trust::store::save_trust_store;
use secretenv::model::identifiers::format::TRUST_LOCAL_V2;
use secretenv::model::trust_store::{KnownKey, KnownKeyApprovalVia, TrustStoreProtected};
use serde_json::Value;
use tempfile::TempDir;

const KID_BOB: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
const KID_CHARLIE: &str = "C4AR1E00C4AR1E00C4AR1E00C4AR1E00";
const DISPLAY_KID_BOB: &str = "B0B0-B0B0-B0B0-B0B0-B0B0-B0B0-B0B0-B0B0";
const BOB_MEMBER_ID: &str = "bob@example.com";
const CHARLIE_MEMBER_ID: &str = "charlie@example.com";

fn make_known_key(kid: &str, member_id: &str, approved_at: &str) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        member_id: member_id.to_string(),
        approved_at: approved_at.to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

fn save_signed_trust_store(home: &TempDir) {
    let key_ctx = setup_member_key_context(home, ALICE_MEMBER_ID, None);
    let protected = TrustStoreProtected {
        format: TRUST_LOCAL_V2.to_string(),
        owner_member_id: ALICE_MEMBER_ID.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: vec![
            make_known_key(KID_BOB, BOB_MEMBER_ID, "2026-03-29T12:40:00Z"),
            make_known_key(KID_CHARLIE, CHARLIE_MEMBER_ID, "2026-03-29T12:41:00Z"),
        ],
    };
    let document = sign_trust_store(&protected, &key_ctx.signing_key, &key_ctx.kid).unwrap();
    let path = trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    save_trust_store(&path, &document).unwrap();
}

#[test]
fn test_trust_list_succeeds_without_ssh_agent() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);

    let assert = cargo::cargo_bin_cmd!("secretenv")
        .arg("trust")
        .arg("list")
        .arg("--home")
        .arg(home.path())
        .env("SECRETENV_SSH_SIGNING_METHOD", "ssh-agent")
        .env_remove("SSH_AUTH_SOCK")
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains(BOB_MEMBER_ID),
        "expected trust list output to contain '{}', got: {}",
        BOB_MEMBER_ID,
        stderr
    );
    assert!(
        stderr.contains(CHARLIE_MEMBER_ID),
        "expected trust list output to contain '{}', got: {}",
        CHARLIE_MEMBER_ID,
        stderr
    );
    assert!(
        stderr.contains(DISPLAY_KID_BOB),
        "expected trust list output to contain display kid '{}', got: {}",
        DISPLAY_KID_BOB,
        stderr
    );
    assert.stderr(predicate::str::contains(BOB_MEMBER_ID));
}

#[test]
fn test_trust_list_json_keeps_canonical_kid() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);

    let assert = cargo::cargo_bin_cmd!("secretenv")
        .arg("trust")
        .arg("list")
        .arg("--json")
        .arg("--home")
        .arg(home.path())
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let output: Value = serde_json::from_str(&stdout).expect("Output should be valid JSON");
    let known_keys = output["known_keys"]
        .as_array()
        .expect("known_keys should be an array");
    let bob = known_keys
        .iter()
        .find(|entry| entry["member_id"] == BOB_MEMBER_ID)
        .expect("bob entry should exist");

    assert_eq!(bob["kid"], KID_BOB);
}

#[cfg(unix)]
#[test]
fn test_trust_remove_prints_insecure_permission_warning() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);
    let trust_path = trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let assert = cmd()
        .arg("trust")
        .arg("remove")
        .arg(KID_BOB)
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("Insecure permissions"),
        "expected warning in stderr, got: {}",
        stderr
    );
    assert!(
        stderr.contains("Removed kid"),
        "expected removal confirmation in stderr, got: {}",
        stderr
    );
    assert!(
        stderr.contains(DISPLAY_KID_BOB),
        "expected removal confirmation to contain display kid '{}', got: {}",
        DISPLAY_KID_BOB,
        stderr
    );
}

#[cfg(unix)]
#[test]
fn test_trust_remove_old_identity_option_fails() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("remove")
        .arg(KID_BOB)
        .arg("--home")
        .arg(home.path())
        .arg("--identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("--ssh-identity"));
}

#[cfg(unix)]
#[test]
fn test_trust_list_prints_warning_after_known_key_output() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);
    let trust_path = trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let assert = cmd()
        .arg("trust")
        .arg("list")
        .arg("--home")
        .arg(home.path())
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    let known_key_pos = stderr.find(BOB_MEMBER_ID).unwrap();
    let warning_pos = stderr.find("Warning: Insecure permissions").unwrap();
    assert!(
        known_key_pos < warning_pos,
        "expected known key output before permission warning, got: {}",
        stderr
    );
}

#[test]
fn test_trust_purge_with_force() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("purge")
        .arg("--older-than")
        .arg("1d")
        .arg("--force")
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Purged 2 entry(ies)"));

    cmd()
        .arg("trust")
        .arg("list")
        .arg("--home")
        .arg(home.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("No known keys in trust store"));
}

#[test]
fn test_trust_purge_with_force_short_option() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("purge")
        .arg("--older-than")
        .arg("1d")
        .arg("-f")
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Purged 2 entry(ies)"));
}

#[test]
fn test_trust_purge_without_force_in_non_interactive_mode_error() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("purge")
        .arg("--older-than")
        .arg("1d")
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Non-interactive mode requires --force flag for purge",
        ));
}

#[test]
fn test_trust_purge_yes_option_error() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("purge")
        .arg("--older-than")
        .arg("1d")
        .arg("--yes")
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument '--yes'"));
}
