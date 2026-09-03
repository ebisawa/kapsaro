// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace-related encryption tests

#[cfg(unix)]
use crate::cli::common::{assert_member_set_review_success, kapsaro_std_cmd};
use crate::cli::common::{
    cmd, encrypt_file_with_member_set_review, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace,
    setup_trust_store_for_workspace, update_active_private_key_expires_at,
};
#[cfg(unix)]
use console::strip_ansi_codes;
use kapsaro_test_support::crypto_context::setup_member_key_context;
use kapsaro_test_support::fixture::setup_test_workspace;
use kapsaro_test_support::keygen_helpers::keygen_test;
use std::fs;

/// Warning the CLI prints when a recipient public key is close to expiry.
#[cfg(unix)]
const RECIPIENT_EXPIRY_WARNING: &str =
    "Warning: Recipient public key for 'bob@example.com' expires in";

#[cfg(unix)]
use kapsaro_core::test_support::storage::trust::paths::get_trust_store_file_path;

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
fn test_encrypt_warns_about_insecure_trust_store_permissions() {
    use crate::test_utils::member_handle;
    use std::os::unix::fs::PermissionsExt;

    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let input_path = workspace_dir.join("warn.txt");
    fs::write(&input_path, b"permission check").unwrap();
    let output_path = workspace_dir.join("warn.txt.encrypted");

    let output = cmd()
        .arg("encrypt")
        .arg(&input_path)
        .arg("--out")
        .arg(&output_path)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("KAPSARO_HOME", temp_dir.path())
        .env(
            "KAPSARO_SSH_IDENTITY",
            temp_dir.path().join(".ssh").join("test_ed25519"),
        )
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "encrypt must complete despite an insecure trust store: {stderr}"
    );
    assert!(
        stderr.contains("Insecure permissions 0644"),
        "missing warning: {stderr}"
    );
    assert!(
        stderr.contains("(expected 0600)") && stderr.contains("chmod 0600"),
        "warning must name the required permissions and the fix: {stderr}"
    );
    assert!(
        output_path.exists(),
        "encrypt must still produce its output file"
    );
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

#[cfg(unix)]
#[test]
fn test_encrypt_surfaces_recipient_key_expiry_warning_on_stderr() {
    let (temp_dir, workspace_dir) = setup_workspace_with_expiring_recipient_key();
    let mut command =
        build_expiring_recipient_encrypt_command(&temp_dir, &workspace_dir, "recipient-expiry");

    let output = assert_member_set_review_success(&mut command);

    assert!(output.contains(RECIPIENT_EXPIRY_WARNING), "{output}");
    assert!(output.contains(". Expires at: "), "{output}");
    assert!(!output.contains("\n         Expires at: "), "{output}");
}

/// Builds a workspace whose recipient key for Bob is close to expiry, with the
/// resulting member set already approved so encryption needs no review prompt.
#[cfg(unix)]
fn setup_workspace_with_expiring_recipient_key() -> (tempfile::TempDir, std::path::PathBuf) {
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

    (temp_dir, workspace_dir)
}

/// Builds the encrypt command used by the recipient key expiry warning tests.
#[cfg(unix)]
fn build_expiring_recipient_encrypt_command(
    temp_dir: &tempfile::TempDir,
    workspace_dir: &std::path::Path,
    stem: &str,
) -> std::process::Command {
    let input_path = workspace_dir.join(format!("{stem}.txt"));
    fs::write(&input_path, b"warning check").unwrap();

    let mut command = kapsaro_std_cmd();
    command
        .arg("encrypt")
        .arg(&input_path)
        .arg("--out")
        .arg(workspace_dir.join(format!("{stem}.txt.encrypted")))
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir)
        .env("KAPSARO_HOME", temp_dir.path())
        .env(
            "KAPSARO_SSH_IDENTITY",
            temp_dir.path().join(".ssh").join("test_ed25519"),
        );
    command
}

#[cfg(unix)]
#[test]
fn test_encrypt_colors_recipient_key_expiry_warning_when_forced() {
    let (temp_dir, workspace_dir) = setup_workspace_with_expiring_recipient_key();
    let mut command =
        build_expiring_recipient_encrypt_command(&temp_dir, &workspace_dir, "colored-expiry");
    command.env("CLICOLOR_FORCE", "1");

    let output = assert_member_set_review_success(&mut command);

    assert!(
        output.contains(&format!("\u{1b}[33m{}", RECIPIENT_EXPIRY_WARNING)),
        "expected ANSI-colored expiry warning, got: {output}"
    );
    assert!(
        strip_ansi_codes(&output).contains(RECIPIENT_EXPIRY_WARNING),
        "expected warning text to remain intact after stripping ANSI, got: {output}"
    );
}

#[cfg(unix)]
#[test]
fn test_encrypt_prints_expiry_warning_before_output_notice() {
    let (temp_dir, workspace_dir) = setup_workspace_with_expiring_recipient_key();
    let mut command =
        build_expiring_recipient_encrypt_command(&temp_dir, &workspace_dir, "ordered-expiry");

    let output = assert_member_set_review_success(&mut command);

    let warning_position = output
        .find(RECIPIENT_EXPIRY_WARNING)
        .unwrap_or_else(|| panic!("expected expiry warning, got: {output}"));
    let notice_position = output
        .find("Encrypted to")
        .unwrap_or_else(|| panic!("expected output notice, got: {output}"));
    assert!(
        warning_position < notice_position,
        "expected the expiry warning before the output notice, got: {output}"
    );
}
