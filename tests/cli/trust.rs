// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for trust commands.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::cli::common::{
    cmd, copy_dir_all, save_trust_store_signed_by_active_key, ALICE_MEMBER_HANDLE,
    TRUST_STORE_STORED_AT,
};
#[cfg(unix)]
use crate::cli::common::{kapsaro_std_cmd, run_command_with_pty_script_at_prompt};
use crate::test_utils::member_handle;
use assert_cmd::cargo;
use kapsaro_core::test_support::domain::trust_store::RecipientSetRecord;
use kapsaro_core::test_support::helpers::time::format_timestamp_rfc3339;
use kapsaro_core::test_support::storage::trust::paths::get_trust_store_file_path;
use kapsaro_test_support::fixture::setup_test_keystore_from_fixtures;
use kapsaro_test_support::trust_store_state::{build_known_key, build_recipient_set};
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

const KID_BOB: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
const KID_CHARLIE: &str = "C4AR1E00C4AR1E00C4AR1E00C4AR1E00";
const DISPLAY_KID_BOB: &str = "B0B0-B0B0-B0B0-B0B0-B0B0-B0B0-B0B0-B0B0";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";
const CHARLIE_MEMBER_HANDLE: &str = "charlie@example.com";
const SID_OLD: &str = "00000000-0000-4000-8000-000000000201";
const SID_NEW: &str = "00000000-0000-4000-8000-000000000202";

fn save_signed_trust_store(home: &TempDir) -> String {
    save_signed_trust_store_with_recipient_sets(home, Vec::new())
}

fn invalidate_trust_store_signature(path: &std::path::Path) {
    let mut document: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let signature = document["signature"]["sig"]
        .as_str()
        .expect("signed trust store must contain a signature");
    let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
    document["signature"]["sig"] = Value::String(format!("{replacement}{}", &signature[1..]));
    fs::write(path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
}

fn save_signed_trust_store_with_recipient_sets(
    home: &TempDir,
    recipient_sets: Vec<RecipientSetRecord>,
) -> String {
    save_trust_store_signed_by_active_key(
        home,
        ALICE_MEMBER_HANDLE,
        TRUST_STORE_STORED_AT,
        vec![
            build_known_key(KID_BOB, BOB_MEMBER_HANDLE, Some("2026-03-29T12:40:00Z")),
            build_known_key(
                KID_CHARLIE,
                CHARLIE_MEMBER_HANDLE,
                Some("2026-03-29T12:41:00Z"),
            ),
        ],
        recipient_sets,
    )
}

fn save_signed_trust_store_with_default_recipient_sets(home: &TempDir) {
    // Keep approval timestamps relative to the current time so purge tests
    // with "--older-than 1d" stay valid regardless of the execution date.
    let now = time::OffsetDateTime::now_utc();
    let old_approved_at = format_timestamp_rfc3339(now - time::Duration::days(30)).unwrap();
    let new_approved_at = format_timestamp_rfc3339(now).unwrap();
    save_signed_trust_store_with_recipient_sets(
        home,
        vec![
            build_recipient_set(SID_OLD, &[KID_BOB], &old_approved_at),
            build_recipient_set(SID_NEW, &[KID_BOB, KID_CHARLIE], &new_approved_at),
        ],
    );
}

fn install_secondary_member_fixture(home: &TempDir, member_handle: &str) {
    let secondary_home = setup_test_keystore_from_fixtures(member_handle);
    let source = secondary_home.path().join("keys").join(member_handle);
    let destination = home.path().join("keys").join(member_handle);
    copy_dir_all(&source, &destination);
}

#[test]
fn test_trust_list_succeeds_without_ssh_agent() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    let assert = cargo::cargo_bin_cmd!("kapsaro")
        .arg("trust")
        .arg("keys")
        .arg("list")
        .arg("--home")
        .arg(home.path())
        .env("KAPSARO_SSH_SIGNING_METHOD", "ssh-agent")
        .env_remove("SSH_AUTH_SOCK")
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains(BOB_MEMBER_HANDLE),
        "expected trust list output to contain '{}', got: {}",
        BOB_MEMBER_HANDLE,
        stderr
    );
    assert!(
        stderr.contains(CHARLIE_MEMBER_HANDLE),
        "expected trust list output to contain '{}', got: {}",
        CHARLIE_MEMBER_HANDLE,
        stderr
    );
    assert!(
        stderr.contains(DISPLAY_KID_BOB),
        "expected trust list output to contain display kid '{}', got: {}",
        DISPLAY_KID_BOB,
        stderr
    );
    assert.stderr(predicate::str::contains(BOB_MEMBER_HANDLE));
}

#[test]
fn test_trust_list_explicit_member_succeeds_with_invalid_config() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    fs::write(home.path().join("config.toml"), "member_handle = [\n").unwrap();

    cmd()
        .arg("trust")
        .arg("keys")
        .arg("list")
        .arg("--home")
        .arg(home.path())
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .assert()
        .success()
        .stderr(predicate::str::contains(BOB_MEMBER_HANDLE));
}

/// The listing reports the approvals it read and the permission problem it met
/// on the way, and the warning has to survive alongside the listing output.
#[cfg(unix)]
#[test]
fn test_trust_list_warns_about_insecure_trust_store_permissions() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let assert = cmd()
        .arg("trust")
        .arg("keys")
        .arg("list")
        .arg("--home")
        .arg(home.path())
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains(BOB_MEMBER_HANDLE),
        "expected the known key listing in stderr, got: {}",
        stderr
    );
    assert!(
        stderr.contains("Insecure permissions 0644"),
        "expected the insecure permission warning in stderr, got: {}",
        stderr
    );
    assert!(
        stderr.contains("(expected 0600)") && stderr.contains("chmod 0600"),
        "expected the warning to name the expected mode and the repair, got: {}",
        stderr
    );
}

#[test]
fn test_trust_list_json_keeps_canonical_kid() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    let assert = cargo::cargo_bin_cmd!("kapsaro")
        .arg("trust")
        .arg("keys")
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
        .find(|entry| entry["subject_handle"] == BOB_MEMBER_HANDLE)
        .expect("bob entry should exist");

    assert_eq!(bob["kid"], KID_BOB);
}

#[test]
fn test_trust_recipients_list_text_shows_sid_hash_and_kids() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);

    let assert = cmd()
        .arg("trust")
        .arg("recipients")
        .arg("list")
        .arg("--home")
        .arg(home.path())
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains(SID_OLD),
        "expected old sid, got: {}",
        stderr
    );
    assert!(
        stderr.contains(SID_NEW),
        "expected new sid, got: {}",
        stderr
    );
    assert!(
        stderr.contains("hash:"),
        "expected hash line, got: {}",
        stderr
    );
    assert!(
        stderr.contains(DISPLAY_KID_BOB),
        "expected display kid, got: {}",
        stderr
    );
}

#[test]
fn test_trust_recipients_list_json_keeps_canonical_fields() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);

    let assert = cmd()
        .arg("trust")
        .arg("recipients")
        .arg("list")
        .arg("--json")
        .arg("--home")
        .arg(home.path())
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let output: Value = serde_json::from_str(&stdout).expect("Output should be valid JSON");
    let recipient_sets = output["recipient_sets"]
        .as_array()
        .expect("recipient_sets should be an array");
    let old_record = recipient_sets
        .iter()
        .find(|entry| entry["sid"] == SID_OLD)
        .expect("old recipient set should exist");

    assert_eq!(old_record["recipient_kids"][0], KID_BOB);
    assert!(old_record["recipient_set_hash"].as_str().unwrap().len() > 20);
}

#[test]
fn test_trust_recipients_remove_deletes_requested_sid() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);

    cmd()
        .arg("trust")
        .arg("recipients")
        .arg("remove")
        .arg(SID_OLD)
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Removed recipient set"));
}

#[cfg(unix)]
#[test]
fn test_trust_remove_warns_about_insecure_trust_store_permissions() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let assert = cmd()
        .arg("trust")
        .arg("keys")
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
        stderr.contains("from trust store"),
        "expected the removal summary in stderr, got: {}",
        stderr
    );
    assert!(
        stderr.contains("Insecure permissions 0644"),
        "expected the insecure permission warning in stderr, got: {}",
        stderr
    );
    assert!(
        stderr.contains("(expected 0600)") && stderr.contains("chmod 0600"),
        "warning must name the required permissions and the fix, got: {}",
        stderr
    );
}

#[test]
fn test_trust_remove_requires_member_handle_when_keystore_is_ambiguous() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    install_secondary_member_fixture(&home, BOB_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    let assert = cmd()
        .arg("trust")
        .arg("keys")
        .arg("remove")
        .arg(KID_BOB)
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    let (first_line, body) = stderr
        .split_once('\n')
        .expect("member handle error should render as multiple lines");
    assert_eq!(
        first_line,
        "\u{1b}[31mError: member handle not configured.\u{1b}[0m"
    );
    assert!(
        !body.contains("\u{1b}[31m"),
        "follow-up guidance should not be colored red: {stderr}"
    );
}

#[test]
fn test_trust_remove_accepts_member_handle_when_keystore_is_ambiguous() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    install_secondary_member_fixture(&home, BOB_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("keys")
        .arg("remove")
        .arg(KID_BOB)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Removed kid"));
}

#[test]
fn test_trust_remove_accepts_display_kid() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("keys")
        .arg("remove")
        .arg(DISPLAY_KID_BOB)
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPLAY_KID_BOB));
}

#[test]
fn test_trust_remove_accepts_unique_prefix_kid() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("keys")
        .arg("remove")
        .arg("B0B0")
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .success()
        .stderr(predicate::str::contains(DISPLAY_KID_BOB));
}

/// A reset takes the whole store, so the key the operator asked to remove is
/// gone with it. Retrying the removal against the empty cache would only report
/// the store as missing, which reads as a failure for a command that did what
/// it was asked.
#[cfg(unix)]
#[test]
fn test_trust_keys_remove_after_a_reset_reports_an_empty_store() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    invalidate_trust_store_signature(&trust_path);
    let mut command = kapsaro_std_cmd();
    command
        .arg("trust")
        .arg("keys")
        .arg("remove")
        .arg(KID_BOB)
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"));

    let result = run_command_with_pty_script_at_prompt(
        &mut command,
        "continue with an empty trust cache?",
        || {},
        b"y",
        &[],
    );

    assert!(result.status.success(), "{}", result.output);
    assert!(result.output.contains("Deleted local trust store"));
    assert!(result
        .output
        .contains("Trust store was reset, so there was no approved key left to remove"));
    assert!(!trust_path.exists());
}

#[cfg(unix)]
#[test]
fn test_trust_recipients_remove_after_a_reset_reports_an_empty_store() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    invalidate_trust_store_signature(&trust_path);
    let mut command = kapsaro_std_cmd();
    command
        .arg("trust")
        .arg("recipients")
        .arg("remove")
        .arg(SID_OLD)
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"));

    let result = run_command_with_pty_script_at_prompt(
        &mut command,
        "continue with an empty trust cache?",
        || {},
        b"y",
        &[],
    );

    assert!(result.status.success(), "{}", result.output);
    assert!(result
        .output
        .contains("Trust store was reset, so there was no recipient set left to remove"));
    assert!(!trust_path.exists());
}

#[test]
fn test_trust_purge_with_force() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("keys")
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
        .arg("keys")
        .arg("list")
        .arg("--home")
        .arg(home.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("No known keys in trust store"));
}

/// `--older-than` shares the relative duration format `--valid-for` uses, so a
/// month is one of the units it accepts.
#[test]
fn test_trust_purge_accepts_a_duration_in_months() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("keys")
        .arg("purge")
        .arg("--older-than")
        .arg("1m")
        .arg("--force")
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Purged 2 entry(ies)"));
}

/// Weeks are outside the accepted unit set, and the message names the units
/// that are accepted so the operator can correct the argument.
#[test]
fn test_trust_purge_rejects_a_duration_in_weeks() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("keys")
        .arg("purge")
        .arg("--older-than")
        .arg("1w")
        .arg("--force")
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Invalid duration '1w'. Expected <number><unit> with unit d, m or y",
        ));
}

#[test]
fn test_trust_purge_accepts_member_handle_when_keystore_is_ambiguous() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    install_secondary_member_fixture(&home, BOB_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("keys")
        .arg("purge")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
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
}

#[test]
fn test_trust_purge_without_force_in_non_interactive_mode_error() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("keys")
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

/// A store replaced while the operator was reading the purge preview no longer
/// holds what they reviewed, so the command reports the conflict and leaves the
/// file alone. Offering to delete it here would let a mid-flight replacement
/// walk the operator into discarding every pinned key.
#[cfg(unix)]
#[test]
fn test_trust_purge_reports_a_conflict_when_the_reviewed_store_is_replaced() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let mut command = kapsaro_std_cmd();
    command
        .arg("trust")
        .arg("keys")
        .arg("purge")
        .arg("--older-than")
        .arg("1d")
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"));

    let result = run_command_with_pty_script_at_prompt(
        &mut command,
        "Proceed?",
        || fs::write(&trust_path, "invalid trust store").unwrap(),
        b"y",
        &[],
    );

    assert!(!result.status.success(), "{}", result.output);
    assert!(result.output.contains("changed since this command read it"));
    assert_eq!(
        fs::read_to_string(&trust_path).unwrap(),
        "invalid trust store"
    );
}

/// The replacement a purge has to catch is a store that still verifies. Signed
/// by the same owner key and readable in full, it clears every check the write
/// path applies to the bytes, so only the binding to the reviewed content tells
/// the command that the entries it listed are no longer the ones on disk.
#[cfg(unix)]
#[test]
fn test_trust_purge_reports_a_conflict_when_the_reviewed_store_is_replaced_by_a_valid_store() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let mut command = kapsaro_std_cmd();
    command
        .arg("trust")
        .arg("keys")
        .arg("purge")
        .arg("--older-than")
        .arg("1d")
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"));

    let result = run_command_with_pty_script_at_prompt(
        &mut command,
        "Proceed?",
        || {
            save_trust_store_signed_by_active_key(
                &home,
                ALICE_MEMBER_HANDLE,
                TRUST_STORE_STORED_AT,
                vec![build_known_key(
                    KID_CHARLIE,
                    CHARLIE_MEMBER_HANDLE,
                    Some("2026-03-29T12:41:00Z"),
                )],
                Vec::new(),
            );
        },
        b"y",
        &[],
    );

    assert!(!result.status.success(), "{}", result.output);
    assert!(result.output.contains("changed since this command read it"));
    let stored: Value = serde_json::from_slice(&fs::read(&trust_path).unwrap()).unwrap();
    let known_keys = stored["protected"]["known_keys"].as_array().unwrap();
    assert_eq!(known_keys.len(), 1);
    assert_eq!(known_keys[0]["kid"].as_str(), Some(KID_CHARLIE));
}

#[cfg(unix)]
#[test]
fn test_trust_purge_reset_at_list_time_exits_with_empty_result() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    invalidate_trust_store_signature(&trust_path);
    let mut command = kapsaro_std_cmd();
    command
        .arg("trust")
        .arg("keys")
        .arg("purge")
        .arg("--older-than")
        .arg("1d")
        .arg("--force")
        .arg("--home")
        .arg(home.path())
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"));

    let result = run_command_with_pty_script_at_prompt(
        &mut command,
        "continue with an empty trust cache?",
        || {},
        b"y",
        &[],
    );

    assert!(result.status.success(), "{}", result.output);
    assert!(result.output.contains("Deleted local trust store"));
    // The store was discarded whole, so the summary says that rather than
    // reporting a purge count that reads as "nothing happened".
    assert!(result
        .output
        .contains("Trust store was reset, so there were no known keys left to purge"));
    assert!(!trust_path.exists());
}

#[test]
fn test_trust_recipients_purge_with_force_removes_only_old_records() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);

    cmd()
        .arg("trust")
        .arg("recipients")
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
        .stderr(predicate::str::contains("Purged 1 recipient set(s)"));

    cmd()
        .arg("trust")
        .arg("recipients")
        .arg("list")
        .arg("--home")
        .arg(home.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("recipient set(s)"));
}

#[test]
fn test_trust_recipients_purge_without_force_in_non_interactive_mode_error() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);

    cmd()
        .arg("trust")
        .arg("recipients")
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

/// Find the kid of the key a member holds that is not the one named.
fn find_other_kid(home: &TempDir, member_handle: &str, known_kid: &str) -> String {
    let member_dir = home.path().join("keys").join(member_handle);
    fs::read_dir(&member_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_str().unwrap().to_string())
        .find(|kid| kid != known_kid)
        .expect("a second key must exist")
}

fn generate_and_activate_second_key(home: &TempDir) {
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .arg("--home")
        .arg(home.path())
        .assert()
        .success();
}

/// Rotating the signing key and removing the old one is ordinary maintenance,
/// so it must complete without ever proposing to delete the trust store.
#[test]
fn test_key_rotation_removes_the_previous_signer_without_a_reset_prompt() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let previous_kid = save_signed_trust_store(&home);
    generate_and_activate_second_key(&home);

    let assert = cmd()
        .arg("key")
        .arg("remove")
        .arg(&previous_kid)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .arg("--home")
        .arg(home.path())
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.contains("Re-signed local trust store"),
        "the trust store signature must move before the key goes, got: {stderr}"
    );
    assert!(!home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(&previous_kid)
        .exists());

    cmd()
        .arg("trust")
        .arg("keys")
        .arg("list")
        .arg("--home")
        .arg(home.path())
        .assert()
        .success()
        .stderr(predicate::str::contains(BOB_MEMBER_HANDLE));
}

#[test]
fn test_trust_resign_moves_the_signature_to_the_active_key() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let previous_kid = save_signed_trust_store(&home);
    generate_and_activate_second_key(&home);
    let rotated_kid = find_other_kid(&home, ALICE_MEMBER_HANDLE, &previous_kid);

    cmd()
        .arg("trust")
        .arg("resign")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .arg("--home")
        .arg(home.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("Re-signed local trust store for"));

    let path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(document["signature"]["kid"], rotated_kid);
    assert_eq!(document["protected"]["updated_at"], "2026-03-29T12:34:56Z");
}

/// `trust resign` is the repair for a signer key whose public half is gone, so
/// it names that key and the way back rather than offering to delete the store.
#[test]
fn test_trust_resign_reports_a_missing_signer_public_key_without_a_reset_prompt() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    install_secondary_member_fixture(&home, BOB_MEMBER_HANDLE);
    let previous_kid = save_signed_trust_store(&home);
    generate_and_activate_second_key(&home);
    fs::remove_file(
        home.path()
            .join("keys")
            .join(ALICE_MEMBER_HANDLE)
            .join(&previous_kid)
            .join("public.json"),
    )
    .unwrap();

    let assert = cmd()
        .arg("trust")
        .arg("resign")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .arg("--home")
        .arg(home.path())
        .env("KAPSARO_MEMBER_HANDLE", BOB_MEMBER_HANDLE)
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("public.json"),
        "expected the restore path in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("trusted backup or known-good copy"),
        "expected the trusted-copy hint in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("owner-only permissions"),
        "expected the permission hint in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("kapsaro trust resign --member-handle alice@example.com"),
        "expected the re-signing hint in stderr, got: {stderr}"
    );
    assert!(!stderr.contains("kapsaro key export"), "got: {stderr}");
    assert!(
        get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE)).exists(),
        "the trust store must still be on disk"
    );
}

#[test]
fn test_trust_resign_reports_a_store_already_signed_by_the_active_key() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    cmd()
        .arg("trust")
        .arg("resign")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .arg("--home")
        .arg(home.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("already signed by kid"));
}
