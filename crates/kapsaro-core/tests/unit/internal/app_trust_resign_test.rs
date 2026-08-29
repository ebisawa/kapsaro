// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests the explicit trust store re-signing command.
//! Covers signer rotation, the already-current case, and refusal to re-sign unverifiable content.

use std::fs;

use crate::app::trust::resign::resign_trust_store_command;
use crate::app_test_utils::{
    build_test_command_options, build_test_execution_context, load_test_trust_store,
    rotate_active_key, save_test_trust_store_signed_by_active_key,
};
use crate::io::trust::paths::get_trust_store_file_path;
use crate::model::identity::Kid;
use crate::test_utils::{member_handle, setup_test_keystore_from_fixtures, ALICE_MEMBER_HANDLE};
use crate::ErrorKind;
use tempfile::TempDir;

const STORED_AT: &str = "2026-03-29T12:34:56Z";

fn save_signed_trust_store(home: &TempDir) -> String {
    save_test_trust_store_signed_by_active_key(home, ALICE_MEMBER_HANDLE, STORED_AT)
}

fn invalidate_signature(home: &TempDir) {
    let path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let signature = document["signature"]["sig"].as_str().unwrap().to_string();
    let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
    document["signature"]["sig"] =
        serde_json::Value::String(format!("{replacement}{}", &signature[1..]));
    fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
}

#[test]
fn test_resign_moves_the_signature_to_the_active_key() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let previous_kid = save_signed_trust_store(&home);
    let rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = resign_trust_store_command(&options, &execution).unwrap();

    assert!(result.resigned);
    assert_eq!(result.owner_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(result.previous_signer_kid, previous_kid);
    assert_eq!(result.signer_kid, rotated_kid.as_str());
    let stored = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the re-signed trust store must verify against the rotated key");
    assert_eq!(
        stored.signer_kid.as_ref().map(Kid::as_str),
        Some(rotated_kid.as_str())
    );
    assert_eq!(stored.protected.updated_at, STORED_AT);
}

#[test]
fn test_resign_leaves_a_store_already_signed_by_the_active_key_untouched() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let signer_kid = save_signed_trust_store(&home);
    let path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let before = fs::read(&path).unwrap();
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = resign_trust_store_command(&options, &execution).unwrap();

    assert!(!result.resigned);
    assert_eq!(result.previous_signer_kid, signer_kid);
    assert_eq!(result.signer_kid, signer_kid);
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn test_resign_refuses_a_trust_store_that_does_not_verify() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    invalidate_signature(&home);
    rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let error = resign_trust_store_command(&options, &execution)
        .expect_err("content that fails verification must not be re-signed");

    assert_eq!(error.kind(), ErrorKind::Crypto);
    assert_eq!(error.recovery(), Some("E_TRUST_STORE_RESET_REQUIRED"));
}

/// A signer key whose public half is gone is what `trust resign` exists to
/// repair, so it is reported with the rule that names the recovery route rather
/// than as content that changed.
#[test]
fn test_resign_reports_a_signer_key_the_keystore_no_longer_holds() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let previous_kid = save_signed_trust_store(&home);
    rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    fs::remove_file(
        home.path()
            .join("keys")
            .join(ALICE_MEMBER_HANDLE)
            .join(&previous_kid)
            .join("public.json"),
    )
    .unwrap();
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let error = resign_trust_store_command(&options, &execution)
        .expect_err("a store whose signer public key is gone cannot be re-signed");
    let message = error.format_user_message();

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_TRUST_SIGNER_KEY_MISSING"));
    assert!(message.contains("public.json"), "got: {message}");
    assert!(message.contains("kapsaro trust resign"), "got: {message}");
}

#[test]
fn test_resign_reports_an_absent_trust_store() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let error = resign_trust_store_command(&options, &execution)
        .expect_err("there is no trust store to re-sign");

    assert_eq!(error.kind(), ErrorKind::NotFound);
}
