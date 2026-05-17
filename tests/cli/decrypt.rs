// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for decrypt command
//!
//! Tests the decrypt command with CommonOptions, member_handle resolution, and file-enc format

use crate::cli::common::{
    cmd, encrypt_file_with_member_set_review, setup_workspace, ALICE_MEMBER_HANDLE,
    TEST_MEMBER_HANDLE,
};
use crate::test_utils::{build_expiring_soon_timestamp, update_active_private_key_expires_at};
use predicates::prelude::*;
use secretenv_core::cli_api::test_support::domain::wire::private_key::PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256;
use secretenv_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;
use secretenv_core::cli_api::test_support::storage::keystore::member::find_active_key_document;
use std::fs;
use tempfile::TempDir;

/// Create a test keystore with a private key
fn build_test_keystore(temp_dir: &TempDir, member_handle: &str, kid: &str) -> std::path::PathBuf {
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid_dir = member_dir.join(kid);
    fs::create_dir_all(&kid_dir).unwrap();

    // Create active file
    fs::write(member_dir.join("active"), kid).unwrap();

    // Create a dummy private.json (minimal structure for testing)
    let ikm_salt = encode_base64url_nopad(&[0u8; 32]);
    let hkdf_salt = encode_base64url_nopad(&[1u8; 32]);
    let private_json = format!(
        r#"{{
    "protected": {{
        "format": "secretenv:format:private-key@7",
        "subject_handle": "{}",
        "kid": "{}",
        "alg": {{
            "kdf": "{}",
            "fpr": "SHA256:dummy",
            "ikm_salt": "{}",
            "hkdf_salt": "{}",
            "aead": "xchacha20-poly1305"
        }},
        "created_at": "2026-01-16T00:00:00Z",
        "expires_at": "2027-01-16T00:00:00Z"
    }},
    "encrypted": {{
        "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ct": "dGVzdA"
    }}
}}"#,
        member_handle, kid, PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256, ikm_salt, hkdf_salt
    );
    fs::write(kid_dir.join("private.json"), private_json).unwrap();

    keystore_root
}

/// Create a minimal test file-enc v5 file
fn save_test_encrypted_file(path: &std::path::Path) {
    let content = r#"{
  "protected": {
    "format": "secretenv:format:file-enc@5",
    "sid": "550e8400-e29b-41d4-a716-446655440000",
    "wrap": [],
    "payload": {
      "protected": {
        "format": "secretenv:format:file-enc:payload@5",
        "sid": "550e8400-e29b-41d4-a716-446655440000",
        "alg": {
          "aead": "xchacha20-poly1305"
        }
      },
      "encrypted": {
        "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ct": "dGVzdA"
      }
    },
    "created_at": "2026-01-19T10:00:00Z",
    "updated_at": "2026-01-19T10:00:00Z"
  },
  "signature": {
    "alg": "eddsa-ed25519",
    "kid": "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    "sig": "dGVzdA"
  }
}"#;
    fs::write(path, content).unwrap();
}

#[test]
fn test_decrypt_help_aligns_multiline_usage() {
    cmd()
        .arg("decrypt")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Usage: secretenv decrypt [OPTIONS] <INPUT> (--out <OUT> | --stdout)\n       secretenv decrypt [OPTIONS] --stdin (--out <OUT> | --stdout)",
        ));
}

#[test]
fn test_decrypt_missing_input() {
    cmd()
        .arg("decrypt")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "required arguments were not provided",
        ));
}

// ============================================================================
// Format detection tests
// ============================================================================

#[test]
fn test_decrypt_rejects_kv_enc_format() {
    // kv-enc format should be rejected with guidance to use `get` command
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path();

    let encrypted_path = test_dir.join("test.kv");
    let content = r#":SECRETENV_KV 6
:HEAD eyJzaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJjcmVhdGVkX2F0IjoiMjAyNC0wMS0wMVQwMDowMDowMFoiLCJ1cGRhdGVkX2F0IjoiMjAyNC0wMS0wMVQwMDowMDowMFoifQ
:WRAP eyJ3cmFwIjpbeyJtX2lkIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJraWQiOiIwMUhURVNUIiwiZW5jX2NrIjoiZHVtbXkifV19
DATABASE_URL eyJ2IjozLCJrIjoiREFUQUJBU0VfVVJMIiwiZSI6ImR1bW15In0
"#;
    fs::write(&encrypted_path, content).unwrap();

    build_test_keystore(
        &temp_dir,
        ALICE_MEMBER_HANDLE,
        "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    );

    cmd()
        .arg("decrypt")
        .arg(encrypted_path.to_str().unwrap())
        .arg("--out")
        .arg(test_dir.join("out.dat").to_str().unwrap())
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("SECRETENV_HOME", test_dir.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Expected file-enc format"));
}

#[test]
fn test_decrypt_rejects_unknown_format() {
    // Test that decrypt rejects files with unknown format
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path();

    // Create a file with unknown content
    let unknown_path = test_dir.join("unknown.txt");
    let content = "This is just some random text that doesn't match any format\n";
    fs::write(&unknown_path, content).unwrap();

    build_test_keystore(
        &temp_dir,
        ALICE_MEMBER_HANDLE,
        "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    );

    // Try to decrypt unknown file - should fail with specific error
    cmd()
        .arg("decrypt")
        .arg(unknown_path.to_str().unwrap())
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("SECRETENV_HOME", test_dir.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Expected file-enc format"));
}

// ============================================================================
// Roundtrip tests
// ============================================================================

#[test]
fn test_decrypt_file_enc_roundtrip_with_out() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // 暗号化するテストデータ
    let original_content = b"SECRET_VALUE=hello_world\n";
    let input_file = home_dir.path().join("secret.txt");
    fs::write(&input_file, original_content).unwrap();

    let encrypted_file = home_dir.path().join("secret.txt.encrypted");
    let decrypted_file = home_dir.path().join("decrypted.txt");

    // encrypt で暗号化
    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    assert!(encrypted_file.exists(), "Encrypted file should exist");

    // decrypt --out で復号
    cmd()
        .arg("decrypt")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--out")
        .arg(decrypted_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Decrypted to:"))
        .stderr(predicate::str::contains("decrypted.txt"));

    // 復号されたファイルの内容が元のデータと一致することを確認
    assert!(decrypted_file.exists(), "Decrypted file should exist");
    let decrypted_content = fs::read(&decrypted_file).unwrap();
    assert_eq!(
        decrypted_content, original_content,
        "Decrypted content should match original"
    );
}

#[test]
fn test_decrypt_rejects_tampered_file_enc_signature() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let input_file = home_dir.path().join("tampered-secret.txt");
    fs::write(&input_file, b"SECRET_VALUE=must_not_decrypt\n").unwrap();
    let encrypted_file = home_dir.path().join("tampered-secret.txt.encrypted");
    let decrypted_file = home_dir.path().join("tampered-secret.out");

    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    let content = fs::read_to_string(&encrypted_file).unwrap();
    let mut document: serde_json::Value = serde_json::from_str(&content).unwrap();
    document["signature"]["sig"] = serde_json::Value::String(encode_base64url_nopad(&[0u8; 64]));
    fs::write(
        &encrypted_file,
        serde_json::to_string_pretty(&document).unwrap(),
    )
    .unwrap();

    cmd()
        .arg("decrypt")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--out")
        .arg(decrypted_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Signature verification failed"));

    assert!(
        !decrypted_file.exists(),
        "tampered artifact must not decrypt"
    );
}

#[test]
fn test_decrypt_surfaces_private_key_expiry_warning_on_stderr() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let home_ssh_dir = home_dir.path().join(".ssh");
    fs::create_dir_all(&home_ssh_dir).unwrap();
    fs::copy(&ssh_priv, home_ssh_dir.join("test_ed25519")).unwrap();
    fs::copy(
        ssh_priv.with_extension("pub"),
        home_ssh_dir.join("test_ed25519.pub"),
    )
    .unwrap();
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(home_dir.path(), TEST_MEMBER_HANDLE, &expires_at);
    let active_key = find_active_key_document(TEST_MEMBER_HANDLE, &home_dir.path().join("keys"))
        .unwrap()
        .unwrap();
    fs::write(
        workspace_dir
            .path()
            .join("members/active")
            .join(format!("{TEST_MEMBER_HANDLE}.json")),
        serde_json::to_string_pretty(&active_key.public_key).unwrap(),
    )
    .unwrap();

    let original_content = b"SECRET_VALUE=hello_world\n";
    let input_file = home_dir.path().join("expiry-secret.txt");
    fs::write(&input_file, original_content).unwrap();

    let encrypted_file = home_dir.path().join("expiry-secret.txt.encrypted");
    let decrypted_file = home_dir.path().join("expiry-decrypted.txt");

    let output = encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );
    assert!(
        output.contains("Warning: Private key expires in"),
        "{output}"
    );

    cmd()
        .arg("decrypt")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--out")
        .arg(decrypted_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning: Private key expires in"));
}

#[test]
fn test_decrypt_nonexistent_file_fails() {
    cmd()
        .arg("decrypt")
        .arg("/nonexistent/path/to/file.kvenc")
        .assert()
        .failure();
}

#[test]
fn test_decrypt_file_with_stdout_writes_bytes_to_stdout() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let plaintext = b"SECRET_VALUE=hello_stdout\n";
    let input_file = home_dir.path().join("stdout-secret.txt");
    let encrypted_file = home_dir.path().join("stdout-secret.txt.encrypted");
    fs::write(&input_file, plaintext).unwrap();

    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    let assert = cmd()
        .arg("decrypt")
        .arg(&encrypted_file)
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Decrypted to:").not());

    assert_eq!(assert.get_output().stdout, plaintext);
}

#[test]
fn test_decrypt_stdin_with_out_writes_decrypted_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let plaintext = b"SECRET_VALUE=stdin_out\n";
    let input_file = home_dir.path().join("stdin-out-secret.txt");
    let encrypted_file = home_dir.path().join("stdin-out-secret.txt.encrypted");
    let decrypted_file = home_dir.path().join("stdin-out-secret.txt.decrypted");
    fs::write(&input_file, plaintext).unwrap();

    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    let encrypted = fs::read_to_string(&encrypted_file).unwrap();

    cmd()
        .arg("decrypt")
        .arg("--stdin")
        .arg("--out")
        .arg(&decrypted_file)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin(encrypted)
        .assert()
        .success()
        .stderr(predicate::str::contains("stdin-out-secret.txt.decrypted"));

    assert_eq!(fs::read(&decrypted_file).unwrap(), plaintext);
}

#[test]
fn test_decrypt_stdin_with_stdout_writes_bytes_to_stdout() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let plaintext = vec![0x00, 0x01, 0x02, b'a', b'\n', 0xff];
    let input_file = home_dir.path().join("stdin-stdout-secret.bin");
    let encrypted_file = home_dir.path().join("stdin-stdout-secret.bin.encrypted");
    fs::write(&input_file, &plaintext).unwrap();

    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    let assert = cmd()
        .arg("decrypt")
        .arg("--stdin")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin(fs::read_to_string(&encrypted_file).unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Decrypted to:").not());

    assert_eq!(assert.get_output().stdout, plaintext);
}

#[test]
fn test_decrypt_file_requires_out_or_stdout() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let plaintext = b"SECRET_VALUE=needs_output\n";
    let input_file = home_dir.path().join("needs-output.txt");
    let encrypted_file = home_dir.path().join("needs-output.txt.encrypted");
    fs::write(&input_file, plaintext).unwrap();

    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    cmd()
        .arg("decrypt")
        .arg(&encrypted_file)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "requires either --out or --stdout",
        ));
}

#[test]
fn test_decrypt_rejects_stdout_and_out_together() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("test.enc");
    let output_file = temp_dir.path().join("output.dat");
    save_test_encrypted_file(&input_file);

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--stdout")
        .arg("--out")
        .arg(&output_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--stdout").and(predicate::str::contains("--out")));
}

#[test]
fn test_decrypt_rejects_input_and_stdin_together() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("test.enc");
    save_test_encrypted_file(&input_file);

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--stdin")
        .arg("--stdout")
        .write_stdin(fs::read_to_string(&input_file).unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("--stdin").and(predicate::str::contains("<INPUT>")));
}
