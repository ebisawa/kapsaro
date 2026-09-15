// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Checks that authenticated global stores must decrypt before child startup.

#![cfg(unix)]

use crate::cli::common::{assert_member_set_review_success, kapsaro_std_cmd, ALICE_MEMBER_HANDLE};
use kapsaro_test_support::crypto_context::setup_member_key_context;
use kapsaro_test_support::fixture::setup_test_keystore_from_fixtures;
use predicates::prelude::*;

fn replace_with_invalid_ciphertext(path: &std::path::Path, local: &tempfile::TempDir) {
    let _env = kapsaro_test_support::guards::EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let key = setup_member_key_context(local, ALICE_MEMBER_HANDLE, None);
    let invalid =
        kapsaro_core::test_support::invalid_ciphertext::resign_kv_with_invalid_ciphertext(
            &std::fs::read_to_string(path).unwrap(),
            &key,
        )
        .unwrap();
    std::fs::write(path, invalid).unwrap();
}

#[test]
#[serial_test::serial]
fn test_global_run_decryption_failure_preserves_child_startup_boundary() {
    let home = tempfile::TempDir::new().unwrap();
    let local = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let command = |args: &[&str]| {
        let mut command = kapsaro_std_cmd();
        command
            .args(args)
            .env("HOME", home.path())
            .env("KAPSARO_HOME", local.path())
            .env(
                "KAPSARO_SSH_IDENTITY",
                local.path().join(".ssh/test_ed25519"),
            );
        command
    };
    assert_cmd::Command::from_std(command(&["init", "-g"]))
        .assert()
        .success();
    let secret = "global-decryption-failure-secret";
    assert_member_set_review_success(&mut command(&["set", "-g", "VALUE", secret]));
    let path = home.path().join(".kapsaro/secrets/default.kvenc");
    replace_with_invalid_ciphertext(&path, &local);
    let inspected = assert_cmd::Command::from_std(command(&["inspect", "--json"]))
        .arg(&path)
        .assert()
        .success();
    let report: serde_json::Value = serde_json::from_slice(&inspected.get_output().stdout).unwrap();
    assert_eq!(report["signature_verification"]["verified"], true);
    let marker = home.path().join("child-started");
    assert_cmd::Command::from_std(command(&[
        "run",
        "-g",
        "--",
        "sh",
        "-c",
        "touch \"$1\"",
        "sh",
    ]))
    .arg(&marker)
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "XChaCha20-Poly1305 decryption failed",
    ))
    .stdout(predicate::str::contains(secret).not())
    .stderr(predicate::str::contains(secret).not());
    assert!(!marker.exists());
}
