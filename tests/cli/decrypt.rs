// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for decrypt command
//!
//! Tests the decrypt command with CommonOptions, member_id resolution, and file-enc format

use crate::cli::common::{
    cmd, setup_workspace, ALICE_MEMBER_ID, BOB_MEMBER_ID, CAROL_MEMBER_ID, DAVE_MEMBER_ID,
    EVE_MEMBER_ID, FRANK_MEMBER_ID, TEST_MEMBER_ID,
};
use crate::test_utils::{build_expiring_soon_timestamp, update_active_private_key_expires_at};
use predicates::prelude::*;
use secretenv::io::keystore::member::find_active_key_document;
use secretenv::model::identifiers::private_key::PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256;
use secretenv::support::codec::base64_public::encode_base64url_nopad;
use std::fs;
use tempfile::TempDir;

/// Create a test keystore with a private key
fn create_test_keystore(temp_dir: &TempDir, member_id: &str, kid: &str) -> std::path::PathBuf {
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_id);
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
        "format": "secretenv.private.key@5",
        "member_id": "{}",
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
        member_id, kid, PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256, ikm_salt, hkdf_salt
    );
    fs::write(kid_dir.join("private.json"), private_json).unwrap();

    keystore_root
}

/// Create a minimal test file-enc v3 file
fn create_test_encrypted_file(path: &std::path::Path) {
    let content = r#"{
  "protected": {
    "format": "secretenv.file@3",
    "sid": "550e8400-e29b-41d4-a716-446655440000",
    "wrap": [],
    "payload": {
      "protected": {
        "format": "secretenv.file.payload@3",
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
fn test_decrypt_help() {
    cmd()
        .arg("decrypt")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Decrypt"));
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

#[test]
fn test_decrypt_with_explicit_member_id() {
    let temp_dir = TempDir::new().unwrap();
    create_test_keystore(
        &temp_dir,
        ALICE_MEMBER_ID,
        "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    );
    let input_file = temp_dir.path().join("test.enc");
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_with_member_id_from_env() {
    let temp_dir = TempDir::new().unwrap();
    let _keystore_root =
        create_test_keystore(&temp_dir, BOB_MEMBER_ID, "XXCXP9PZWD1FXT336XSBT9W1BR5EADN8");
    let input_file = temp_dir.path().join("test.enc");
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_MEMBER_HANDLE", BOB_MEMBER_ID)
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_with_workspace_option() {
    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path().join("workspace");
    fs::create_dir_all(workspace.join("members")).unwrap();
    fs::create_dir_all(workspace.join("secrets")).unwrap();

    let _keystore_root = create_test_keystore(
        &temp_dir,
        CAROL_MEMBER_ID,
        "9N4R1H8VW6PKT3XNC5JY2F9AR8GD7M2Q",
    );
    let input_file = temp_dir.path().join("test.enc");
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace.to_str().unwrap())
        .arg("--member-handle")
        .arg(CAROL_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_accepts_out_option_parsing() {
    let temp_dir = TempDir::new().unwrap();
    let _keystore_root = create_test_keystore(
        &temp_dir,
        DAVE_MEMBER_ID,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
    );
    let input_file = temp_dir.path().join("test.enc");
    let output_file = temp_dir.path().join("output.env");
    create_test_encrypted_file(&input_file);

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(DAVE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_with_kid_option() {
    let temp_dir = TempDir::new().unwrap();
    let _keystore_root =
        create_test_keystore(&temp_dir, EVE_MEMBER_ID, "5EADN8XXCXP9PZWD1FXT336XSBT9W1BR");
    let input_file = temp_dir.path().join("test.enc");
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(EVE_MEMBER_ID)
        .arg("--kid")
        .arg("5EADN8XXCXP9PZWD1FXT336XSBT9W1BR")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_with_display_kid_option() {
    let temp_dir = TempDir::new().unwrap();
    let _keystore_root =
        create_test_keystore(&temp_dir, EVE_MEMBER_ID, "5EADN8XXCXP9PZWD1FXT336XSBT9W1BR");
    let input_file = temp_dir.path().join("test.enc");
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output-display.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(EVE_MEMBER_ID)
        .arg("--kid")
        .arg("5EAD-N8XX-CXP9-PZWD-1FXT-336X-SBT9-W1BR")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure();
}

#[test]
fn test_decrypt_with_prefix_kid_option() {
    let temp_dir = TempDir::new().unwrap();
    let _keystore_root =
        create_test_keystore(&temp_dir, EVE_MEMBER_ID, "5EADN8XXCXP9PZWD1FXT336XSBT9W1BR");
    let input_file = temp_dir.path().join("test.enc");
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output-prefix.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(EVE_MEMBER_ID)
        .arg("--kid")
        .arg("5EAD")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure();
}

#[test]
fn test_decrypt_with_ssh_key_option() {
    let temp_dir = TempDir::new().unwrap();
    let _keystore_root = create_test_keystore(
        &temp_dir,
        FRANK_MEMBER_ID,
        "KANJ8XHG10HW16VD7ADNCXM1WN44J04Q",
    );
    let input_file = temp_dir.path().join("test.enc");
    let ssh_key_file = temp_dir.path().join("test_key");
    fs::write(&ssh_key_file, "dummy ssh key").unwrap();
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(FRANK_MEMBER_ID)
        .arg("-i")
        .arg(ssh_key_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_command_exists() {
    // Test that the command is named "decrypt" not "decrypt-v3"
    cmd().arg("decrypt").arg("--help").assert().success();
}

#[test]
fn test_decrypt_legacy_command_removed() {
    // Test that the old "decrypt-v3" command no longer exists
    cmd()
        .arg("decrypt-v3")
        .arg("--help")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
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
    let content = r#":SECRETENV_KV 3
:HEAD eyJzaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJjcmVhdGVkX2F0IjoiMjAyNC0wMS0wMVQwMDowMDowMFoiLCJ1cGRhdGVkX2F0IjoiMjAyNC0wMS0wMVQwMDowMDowMFoifQ
:WRAP eyJ3cmFwIjpbeyJtX2lkIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJraWQiOiIwMUhURVNUIiwiZW5jX2NrIjoiZHVtbXkifV19
DATABASE_URL eyJ2IjozLCJrIjoiREFUQUJBU0VfVVJMIiwiZSI6ImR1bW15In0
"#;
    fs::write(&encrypted_path, content).unwrap();

    create_test_keystore(
        &temp_dir,
        ALICE_MEMBER_ID,
        "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    );

    cmd()
        .arg("decrypt")
        .arg(encrypted_path.to_str().unwrap())
        .arg("--out")
        .arg(test_dir.join("out.dat").to_str().unwrap())
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", test_dir.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Expected file-enc format"));
}

#[test]
fn test_decrypt_detects_file_enc_format_version3() {
    // Test that decrypt detects file-enc v3 format
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path();

    // Create a minimal file-enc v3 file
    let encrypted_path = test_dir.join("test.json");
    create_test_encrypted_file(&encrypted_path);

    create_test_keystore(
        &temp_dir,
        ALICE_MEMBER_ID,
        "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    );

    // Try to decrypt without --out - should fail with specific error
    cmd()
        .arg("decrypt")
        .arg(encrypted_path.to_str().unwrap())
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", test_dir.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "requires either --out or --stdout",
        ));
}

#[test]
fn test_decrypt_rejects_plain_kv_format() {
    // Test that decrypt rejects plain (unencrypted) kv format
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path();

    // Create a plain dotenv file
    let plain_path = test_dir.join("plain.env");
    let content = "DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n";
    fs::write(&plain_path, content).unwrap();

    create_test_keystore(
        &temp_dir,
        ALICE_MEMBER_ID,
        "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    );

    // Try to decrypt plain file - should fail with specific error
    cmd()
        .arg("decrypt")
        .arg(plain_path.to_str().unwrap())
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
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

    create_test_keystore(
        &temp_dir,
        ALICE_MEMBER_ID,
        "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    );

    // Try to decrypt unknown file - should fail with specific error
    cmd()
        .arg("decrypt")
        .arg(unknown_path.to_str().unwrap())
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
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
    cmd()
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert!(encrypted_file.exists(), "Encrypted file should exist");

    // decrypt --out で復号
    cmd()
        .arg("decrypt")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--out")
        .arg(decrypted_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
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
    update_active_private_key_expires_at(home_dir.path(), TEST_MEMBER_ID, &expires_at);
    let active_key = find_active_key_document(TEST_MEMBER_ID, &home_dir.path().join("keys"))
        .unwrap()
        .unwrap();
    fs::write(
        workspace_dir
            .path()
            .join("members/active")
            .join(format!("{TEST_MEMBER_ID}.json")),
        serde_json::to_string_pretty(&active_key.public_key).unwrap(),
    )
    .unwrap();

    let original_content = b"SECRET_VALUE=hello_world\n";
    let input_file = home_dir.path().join("expiry-secret.txt");
    fs::write(&input_file, original_content).unwrap();

    let encrypted_file = home_dir.path().join("expiry-secret.txt.encrypted");
    let decrypted_file = home_dir.path().join("expiry-decrypted.txt");

    cmd()
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning: Private key expires in"));

    cmd()
        .arg("decrypt")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--out")
        .arg(decrypted_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
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

    let assert = cmd()
        .arg("decrypt")
        .arg(&encrypted_file)
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
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

    let encrypted = fs::read_to_string(&encrypted_file).unwrap();

    cmd()
        .arg("decrypt")
        .arg("--stdin")
        .arg("--out")
        .arg(&decrypted_file)
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
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
    let plaintext = b"SECRET_VALUE=stdin_stdout\n";
    let input_file = home_dir.path().join("stdin-stdout-secret.txt");
    let encrypted_file = home_dir.path().join("stdin-stdout-secret.txt.encrypted");
    fs::write(&input_file, plaintext).unwrap();

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

    let encrypted = fs::read_to_string(&encrypted_file).unwrap();

    let assert = cmd()
        .arg("decrypt")
        .arg("--stdin")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin(encrypted)
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

    cmd()
        .arg("decrypt")
        .arg(&encrypted_file)
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
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
    create_test_encrypted_file(&input_file);

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
    create_test_encrypted_file(&input_file);

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

#[test]
fn test_decrypt_stdin_rejects_kv_enc_format() {
    let temp_dir = TempDir::new().unwrap();
    let content = r#":SECRETENV_KV 3
:HEAD eyJzaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJjcmVhdGVkX2F0IjoiMjAyNC0wMS0wMVQwMDowMDowMFoiLCJ1cGRhdGVkX2F0IjoiMjAyNC0wMS0wMVQwMDowMDowMFoifQ
:WRAP eyJ3cmFwIjpbeyJtX2lkIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJraWQiOiIwMUhURVNUIiwiZW5jX2NrIjoiZHVtbXkifV19
DATABASE_URL eyJ2IjozLCJrIjoiREFUQUJBU0VfVVJMIiwiZSI6ImR1bW15In0
"#;

    create_test_keystore(
        &temp_dir,
        ALICE_MEMBER_ID,
        "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    );

    cmd()
        .arg("decrypt")
        .arg("--stdin")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .write_stdin(content)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Expected file-enc format"));
}

#[test]
fn test_decrypt_stdin_rejects_plain_kv_format() {
    let temp_dir = TempDir::new().unwrap();

    create_test_keystore(
        &temp_dir,
        ALICE_MEMBER_ID,
        "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    );

    cmd()
        .arg("decrypt")
        .arg("--stdin")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .write_stdin("DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Expected file-enc format"));
}

#[test]
fn test_decrypt_stdin_rejects_unknown_format() {
    let temp_dir = TempDir::new().unwrap();

    create_test_keystore(
        &temp_dir,
        ALICE_MEMBER_ID,
        "10HW16VD7ADNCXM1WN44J04QKANJ8XHG",
    );

    cmd()
        .arg("decrypt")
        .arg("--stdin")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .write_stdin("This is just some random text that doesn't match any format\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Expected file-enc format"));
}

#[test]
fn test_decrypt_stdin_stdout_roundtrip_preserves_binary_bytes() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let plaintext = vec![0x00, 0x01, 0x02, b'a', b'\n', 0xff];

    let encrypt = cmd()
        .arg("encrypt")
        .arg("--stdin")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin(plaintext.clone())
        .assert()
        .success();

    let assert = cmd()
        .arg("decrypt")
        .arg("--stdin")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin(encrypt.get_output().stdout.clone())
        .assert()
        .success();

    assert_eq!(assert.get_output().stdout, plaintext);
}
