// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Artifact manipulation, assertion helpers, and file utilities for CLI integration tests.
// Provides KV signature tampering and stderr ordering assertions.

use kapsaro_core::test_support::helpers::codec::base64_public::encode_base64url_nopad;
use kapsaro_core::test_support::wire::schema::document::parse_kv_signature_token;
use kapsaro_core::test_support::wire::token::TokenCodec;
use std::path::Path;

#[cfg(unix)]
pub struct UnapprovedReadFixture {
    pub home: tempfile::TempDir,
    pub workspace: std::path::PathBuf,
    pub ssh_identity: std::path::PathBuf,
    pub artifact_path: std::path::PathBuf,
    pub trust_store_path: std::path::PathBuf,
    pub unapproved_member_handle: &'static str,
    pub unapproved_kid: String,
}

#[cfg(unix)]
pub fn setup_unapproved_file_read_fixture() -> UnapprovedReadFixture {
    use super::review::encrypt_file_with_member_set_review;
    use kapsaro_core::test_support::storage::keystore::storage::list_kids;
    use kapsaro_core::test_support::storage::trust::paths::get_trust_store_file_path;
    use kapsaro_test_support::constants::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
    use kapsaro_test_support::crypto_context::setup_member_key_context;
    use kapsaro_test_support::fixture::setup_test_workspace_from_fixtures;
    use kapsaro_test_support::guards::EnvGuard;
    use kapsaro_test_support::workspace_state::{member_handle, setup_trust_store_for_workspace};

    let _env = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "yes");
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let bob_ctx = setup_member_key_context(&home, BOB_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(home.path(), &workspace, BOB_MEMBER_HANDLE, &bob_ctx);
    let ssh_identity = home.path().join(".ssh").join("test_ed25519");
    let plaintext = home.path().join("unknown-signer.txt");
    let artifact_path = home.path().join("unknown-signer.fileenc");
    std::fs::write(&plaintext, b"MUST_NOT_BE_DECRYPTED\n").unwrap();
    encrypt_file_with_member_set_review(
        &workspace,
        home.path(),
        &ssh_identity,
        &plaintext,
        &artifact_path,
        BOB_MEMBER_HANDLE,
    );
    let trust_store_path =
        get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let unapproved_kid = list_kids(&home.path().join("keys"), BOB_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    assert!(!trust_store_path.exists());
    UnapprovedReadFixture {
        home,
        workspace,
        ssh_identity,
        artifact_path,
        trust_store_path,
        unapproved_member_handle: BOB_MEMBER_HANDLE,
        unapproved_kid,
    }
}

#[cfg(unix)]
pub fn setup_unapproved_kv_read_fixture() -> UnapprovedReadFixture {
    use super::review::set_value_with_member_set_review;
    use kapsaro_core::test_support::storage::keystore::storage::list_kids;
    use kapsaro_core::test_support::storage::trust::paths::get_trust_store_file_path;
    use kapsaro_test_support::constants::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
    use kapsaro_test_support::crypto_context::setup_member_key_context;
    use kapsaro_test_support::fixture::setup_test_workspace_from_fixtures;
    use kapsaro_test_support::guards::EnvGuard;
    use kapsaro_test_support::workspace_state::{member_handle, setup_trust_store_for_workspace};

    let _env = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "yes");
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let alice_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(home.path(), &workspace, ALICE_MEMBER_HANDLE, &alice_ctx);
    let ssh_identity = home.path().join(".ssh").join("test_ed25519");
    set_value_with_member_set_review(
        &workspace,
        home.path(),
        &ssh_identity,
        "SHOULD_NOT_PRINT",
        "must-not-print",
        Some(ALICE_MEMBER_HANDLE),
        None,
    );
    let trust_store_path =
        get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    std::fs::remove_file(&trust_store_path).unwrap();
    let unapproved_kid = list_kids(&home.path().join("keys"), BOB_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let artifact_path = workspace.join("secrets").join("default.kvenc");
    UnapprovedReadFixture {
        home,
        workspace,
        ssh_identity,
        artifact_path,
        trust_store_path,
        unapproved_member_handle: BOB_MEMBER_HANDLE,
        unapproved_kid,
    }
}

#[cfg(unix)]
pub fn setup_unapproved_kv_signer_read_fixture() -> UnapprovedReadFixture {
    use super::review::set_value_with_member_set_review;
    use kapsaro_core::test_support::storage::keystore::storage::list_kids;
    use kapsaro_core::test_support::storage::trust::paths::get_trust_store_file_path;
    use kapsaro_test_support::constants::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
    use kapsaro_test_support::crypto_context::setup_member_key_context;
    use kapsaro_test_support::fixture::setup_test_workspace_from_fixtures;
    use kapsaro_test_support::guards::EnvGuard;
    use kapsaro_test_support::workspace_state::{member_handle, setup_trust_store_for_workspace};

    let _env = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "yes");
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let bob_ctx = setup_member_key_context(&home, BOB_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(home.path(), &workspace, BOB_MEMBER_HANDLE, &bob_ctx);
    let ssh_identity = home.path().join(".ssh").join("test_ed25519");
    set_value_with_member_set_review(
        &workspace,
        home.path(),
        &ssh_identity,
        "SHOULD_NOT_PRINT",
        "must-not-print",
        Some(BOB_MEMBER_HANDLE),
        None,
    );
    let trust_store_path =
        get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let unapproved_kid = list_kids(&home.path().join("keys"), BOB_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    assert!(!trust_store_path.exists());
    let artifact_path = workspace.join("secrets").join("default.kvenc");
    UnapprovedReadFixture {
        home,
        workspace,
        ssh_identity,
        artifact_path,
        trust_store_path,
        unapproved_member_handle: BOB_MEMBER_HANDLE,
        unapproved_kid,
    }
}

/// Overwrites the signature in a kv-enc file with zeroed bytes to simulate tampering.
pub fn tamper_kv_signature(path: &Path) {
    let content = std::fs::read_to_string(path).expect("kv-enc file must be readable");
    let mut lines = Vec::new();
    let mut tampered = false;
    for line in content.lines() {
        if let Some(token) = line.strip_prefix(":SIG ") {
            let mut signature =
                parse_kv_signature_token(token).expect("kv-enc signature token must parse");
            signature.sig = encode_base64url_nopad(&[0u8; 64]);
            let token = TokenCodec::encode(TokenCodec::JsonJcs, &signature)
                .expect("tampered signature token must encode");
            lines.push(format!(":SIG {token}"));
            tampered = true;
        } else {
            lines.push(line.to_string());
        }
    }
    assert!(tampered, "kv-enc file must contain a SIG line");
    std::fs::write(path, format!("{}\n", lines.join("\n"))).expect("kv-enc file must be writable");
}

/// Asserts that `first` appears before `second` in the given stderr bytes.
pub fn assert_stderr_order(stderr: &[u8], first: &str, second: &str) {
    let stderr = String::from_utf8_lossy(stderr);
    let first_index = stderr
        .find(first)
        .unwrap_or_else(|| panic!("Missing '{first}' in stderr: {stderr}"));
    let second_index = stderr
        .find(second)
        .unwrap_or_else(|| panic!("Missing '{second}' in stderr: {stderr}"));
    assert!(
        first_index < second_index,
        "Expected '{first}' before '{second}' in stderr: {stderr}"
    );
}
