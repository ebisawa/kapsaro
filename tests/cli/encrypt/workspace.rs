// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace-related encryption tests

use crate::cli::common::{
    cmd, encrypt_file_with_member_set_review, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace,
    setup_trust_store_for_workspace, update_active_private_key_expires_at,
};
use kapsaro_test_support::crypto_context::setup_member_key_context;
use kapsaro_test_support::fixture::setup_test_workspace;
use kapsaro_test_support::keygen_helpers::keygen_test;
use std::fs;

#[cfg(unix)]
use kapsaro_core::cli_api::test_support::storage::trust::paths::get_trust_store_file_path;

#[test]
fn test_encrypt_rejects_filename_content_mismatch() {
    // When a member file's stem does not match protected.subject_handle, the
    // encrypt path must refuse to run. Otherwise a PR that only edits the
    // existing alice.json could smuggle bob into the current member set.
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let members_dir = workspace_dir.join("members/active");
    let secrets_dir = workspace_dir.join("secrets");

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (_bob_private, mut bob_public) =
        keygen_test(BOB_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    bob_public.protected.subject_handle = BOB_MEMBER_HANDLE.to_string();
    // After the trust store is built, an attacker-controlled commit plants
    // bob's public key under alice's filename. The encrypt path must refuse
    // the mismatched document rather than silently recipient-swap.
    let alice_member_file = members_dir.join(format!("{}.json", ALICE_MEMBER_HANDLE));
    fs::write(
        &alice_member_file,
        serde_json::to_string_pretty(&bob_public).unwrap(),
    )
    .unwrap();

    let input_path = workspace_dir.join("test.bin");
    fs::write(&input_path, b"binary test content").unwrap();
    let encrypted_path = secrets_dir.join("test.encrypted");

    let output = cmd()
        .arg("encrypt")
        .arg(&input_path)
        .arg("--out")
        .arg(&encrypted_path)
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("KAPSARO_HOME", temp_dir.path())
        .env(
            "KAPSARO_SSH_IDENTITY",
            temp_dir.path().join(".ssh").join("test_ed25519"),
        )
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "encrypt must reject stem/content mismatch"
    );
    let msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        msg.contains("Member handle mismatch"),
        "unexpected error: {msg}"
    );
    assert!(
        !encrypted_path.exists(),
        "rejected encrypt must not produce an output file"
    );
}

#[cfg(unix)]
#[test]
fn test_encrypt_surfaces_insecure_trust_store_warning_on_stderr() {
    use std::os::unix::fs::PermissionsExt;

    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_HANDLE);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let input_path = workspace_dir.join("warn.txt");
    fs::write(&input_path, b"warning check").unwrap();
    let output_path = workspace_dir.join("warn.txt.encrypted");
    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");

    let output = encrypt_file_with_member_set_review(
        &workspace_dir,
        temp_dir.path(),
        &ssh_key,
        &input_path,
        &output_path,
        ALICE_MEMBER_HANDLE,
    );
    assert!(output.contains("Insecure permissions"), "{output}");
}

#[test]
fn test_encrypt_surfaces_private_key_expiry_warning_on_stderr() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_HANDLE)
        .unwrap();

    let input_path = workspace_dir.join("expiry.txt");
    fs::write(&input_path, b"warning check").unwrap();
    let output_path = workspace_dir.join("expiry.txt.encrypted");
    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");

    let output = encrypt_file_with_member_set_review(
        &workspace_dir,
        temp_dir.path(),
        &ssh_key,
        &input_path,
        &output_path,
        ALICE_MEMBER_HANDLE,
    );
    assert!(output.contains("Warning: Local key expires in"), "{output}");
    assert!(output.contains(". Expires at: "), "{output}");
    assert!(!output.contains("\n         Expires at: "), "{output}");
}

#[test]
fn test_encrypt_surfaces_recipient_key_expiry_warning_on_stderr() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), BOB_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, BOB_MEMBER_HANDLE)
        .unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let input_path = workspace_dir.join("recipient-expiry.txt");
    fs::write(&input_path, b"warning check").unwrap();
    let output_path = workspace_dir.join("recipient-expiry.txt.encrypted");
    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");

    let output = encrypt_file_with_member_set_review(
        &workspace_dir,
        temp_dir.path(),
        &ssh_key,
        &input_path,
        &output_path,
        ALICE_MEMBER_HANDLE,
    );
    assert!(
        output.contains("Warning: Recipient public key for 'bob@example.com' expires in"),
        "{output}"
    );
    assert!(output.contains(". Expires at: "), "{output}");
    assert!(!output.contains("\n         Expires at: "), "{output}");
}
