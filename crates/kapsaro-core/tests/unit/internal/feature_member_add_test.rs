// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/member_add module

use crate::io::workspace::members::test_support::load_incoming_member_files;
use crate::test_support::operations::member::add::add_member_from_file;
use crate::test_utils::setup_test_workspace;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

use crate::format::codec::base64_public::{encode_base64_standard_nopad, encode_base64url_nopad};
use crate::io::ssh::protocol::constants::ATTESTATION_NAMESPACE;
use crate::io::ssh::protocol::sshsig::build_sshsig_signed_data;
use crate::io::ssh::protocol::wire::encode_ssh_string;
use crate::model::wire::context::SSHSIG_MESSAGE_PUBLIC_KEY_ATTESTATION_V1;
use crate::ErrorKind;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

// Build hostile signed input independently of the application's numeric validation.
fn build_signed_numeric_member(id: u64) -> Value {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let public_bytes = signing_key.verifying_key().to_bytes();
    let mut ssh_blob = encode_ssh_string(b"ssh-ed25519").unwrap();
    ssh_blob.extend(encode_ssh_string(&public_bytes).unwrap());
    let mut body = json!({
        "p": SSHSIG_MESSAGE_PUBLIC_KEY_ATTESTATION_V1,
        "subject_handle": "numeric@example.com",
        "keys": {
            "kem": {"kty": "OKP", "crv": "X25519", "x": encode_base64url_nopad(&[7; 32])},
            "sig": {"kty": "OKP", "crv": "Ed25519", "x": encode_base64url_nopad(&public_bytes)}
        },
        "binding_claims": {"github_account": {"id": id, "login": "numeric"}},
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z"
    });
    let message = serde_jcs::to_vec(&body).unwrap();
    let signed_data = build_sshsig_signed_data(&message, ATTESTATION_NAMESPACE).unwrap();
    body.as_object_mut().unwrap().remove("p");
    body["format"] = json!("kapsaro:format:public-key@1");
    body["attestation"] = json!({
        "method": "ssh-sign",
        "pub": format!("ssh-ed25519 {}", encode_base64_standard_nopad(&ssh_blob)),
        "sig": encode_base64url_nopad(&signing_key.sign(&signed_data).to_bytes())
    });
    body["kid"] = json!(derive_numeric_fixture_kid(&body));
    let signature = signing_key.sign(&serde_jcs::to_vec(&body).unwrap());
    json!({"protected": body, "signature": encode_base64url_nopad(&signature.to_bytes())})
}

fn derive_numeric_fixture_kid(protected: &Value) -> String {
    let digest = Sha256::digest(serde_jcs::to_vec(protected).unwrap());
    let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    (0..32)
        .map(|group| {
            let value = (0..5).fold(0, |value, offset| {
                let bit = group * 5 + offset;
                (value << 1) | ((digest[bit / 8] >> (7 - bit % 8)) & 1)
            });
            alphabet[usize::from(value)] as char
        })
        .collect()
}

#[test]
fn test_add_member_enforces_safe_integer_range_before_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path().join("workspace");
    let incoming = workspace.join("members/incoming");
    fs::create_dir_all(workspace.join("members/active")).unwrap();
    fs::create_dir_all(&incoming).unwrap();
    let export = temp_dir.path().join("numeric.json");
    let valid = build_signed_numeric_member(9_007_199_254_740_991);
    fs::write(&export, serde_json::to_vec(&valid).unwrap()).unwrap();
    add_member_from_file(&workspace, &export, false).unwrap();
    let destination = incoming.join("numeric@example.com.json");
    let original = fs::read(&destination).unwrap();

    let signed = build_signed_numeric_member(9_007_199_254_740_992);
    for id in [9_007_199_254_740_992_u64, 9_007_199_254_740_993] {
        let mut hostile = signed.clone();
        hostile["protected"]["binding_claims"]["github_account"]["id"] = json!(id);
        fs::write(&export, serde_json::to_vec(&hostile).unwrap()).unwrap();
        let error = add_member_from_file(&workspace, &export, true).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Parse, "id = {id}: {error}");
        assert_eq!(fs::read(&destination).unwrap(), original);
        assert_eq!(fs::read_dir(&incoming).unwrap().count(), 1);
    }
}

fn save_tampered_public_key(export_file: &std::path::Path, tamper: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_str(&fs::read_to_string(export_file).unwrap()).unwrap();
    tamper(&mut value);
    fs::write(export_file, serde_json::to_string_pretty(&value).unwrap()).unwrap();
}

#[test]
fn test_add_member_valid_file() {
    // Create workspace with alice as active member
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    // Export alice's public key to a temp file
    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();

    // Create a fresh workspace with no members
    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    let member_handle = add_member_from_file(&workspace_dir2, &export_file, false).unwrap();
    assert_eq!(member_handle, "alice@example.com");

    let incoming = load_incoming_member_files(&workspace_dir2).unwrap();
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].protected.subject_handle, "alice@example.com");
}

#[test]
fn test_add_member_invalid_json() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_dir = temp_dir.path().join("workspace");
    fs::create_dir_all(workspace_dir.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("bad.json");
    fs::write(&export_file, "not json").unwrap();

    let result = add_member_from_file(&workspace_dir, &export_file, false);
    assert!(result.is_err());
}

#[test]
fn test_add_member_file_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_dir = temp_dir.path().join("workspace");
    fs::create_dir_all(workspace_dir.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();

    let result = add_member_from_file(
        &workspace_dir,
        std::path::Path::new("/nonexistent/file.json"),
        false,
    );
    assert!(result.is_err());
}

#[test]
fn test_add_member_duplicate_without_force() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();

    // First add succeeds
    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    add_member_from_file(&workspace_dir2, &export_file, false).unwrap();

    // Second add without force fails
    let result = add_member_from_file(&workspace_dir2, &export_file, false);
    assert!(result.is_err());
}

#[test]
fn test_add_member_duplicate_with_force() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();

    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    add_member_from_file(&workspace_dir2, &export_file, false).unwrap();

    // Second add with force succeeds
    let result = add_member_from_file(&workspace_dir2, &export_file, true);
    assert!(result.is_ok());
}

#[test]
fn test_add_member_invalid_self_signature_error() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();
    save_tampered_public_key(&export_file, |value| {
        value["protected"]["expires_at"] = Value::String("2030-01-01T00:00:00Z".to_string());
    });

    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    let result = add_member_from_file(&workspace_dir2, &export_file, false);
    assert!(result.is_err());
}

#[test]
fn test_add_member_invalid_attestation_error() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();
    save_tampered_public_key(&export_file, |value| {
        value["protected"]["identity"]["attestation"]["pub"] =
            Value::String("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBroken broken@test".to_string());
    });

    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    let result = add_member_from_file(&workspace_dir2, &export_file, false);
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn test_add_member_reads_symlinked_input_file() {
    use std::os::unix::fs::symlink;

    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    symlink(&alice_key_path, &export_file).unwrap();

    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    let member_handle = add_member_from_file(&workspace_dir2, &export_file, false).unwrap();

    assert_eq!(member_handle, "alice@example.com");
}
