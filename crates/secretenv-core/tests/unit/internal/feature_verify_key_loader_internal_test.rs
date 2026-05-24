// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::feature::context::expiry::{
    build_recipient_key_expiry_warning, enforce_recipient_key_not_expired,
};
use crate::feature::key::material::{build_identity_keys, generate_keypairs};
use crate::feature::key::public_key_document::{
    build_attestation, build_public_key, PublicKeyDocumentParams,
};
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::feature::verify::public_key::{
    build_public_key_expiry_warning, verify_public_key_for_verification_context,
    verify_public_key_with_attestation_context, verify_recipient_public_keys,
};
use crate::format::codec::base64_public::decode_base64url_nopad_array;
use crate::format::public_key::AttestationBodyInput;
use crate::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use crate::io::ssh::backend::SignatureBackend;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::protocol::{build_sha256_fingerprint, SshKeyDescriptor};
use crate::model::public_key::PublicKey;
use crate::model::ssh::SshDeterminismStatus;
use crate::model::verification::VerifyingKeySource;
use std::path::Path;

/// Build SSH binding context from test SSH keypair
fn build_test_ssh_context(ssh_key_path: &Path, ssh_pubkey: &str) -> SshBindingContext {
    let fingerprint = build_sha256_fingerprint(ssh_pubkey).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(ssh_key_path.to_path_buf()),
    ));
    SshBindingContext {
        public_key: ssh_pubkey.to_string(),
        fingerprint,
        backend,
        determinism: SshDeterminismStatus::Verified,
    }
}

/// Generate a temp SSH keypair and return (temp_dir, private_key_path, public_key_content)
fn generate_ssh_keypair() -> (tempfile::TempDir, std::path::PathBuf, String) {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let ssh_dir = temp_dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let private_key_path = ssh_dir.join("test_ed25519");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&private_key_path)
        .args(["-N", "", "-C", "test@example.com"])
        .output()
        .expect("Failed to generate SSH keypair");
    let public_key_content = std::fs::read_to_string(ssh_dir.join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    (temp_dir, private_key_path, public_key_content)
}

fn build_test_public_key(expires_at: &str) -> (PublicKey, String) {
    let (ssh_temp, ssh_priv, ssh_pub_content) = generate_ssh_keypair();
    let ssh_context = build_test_ssh_context(&ssh_priv, &ssh_pub_content);

    let keypairs = generate_keypairs().unwrap();
    let keys = build_identity_keys(&keypairs.kem_pk, &keypairs.sig_pk).unwrap();
    let attestation = build_attestation(
        &ssh_context,
        &AttestationBodyInput {
            subject_handle: "test@example.com",
            keys: &keys,
            binding_claims: None,
            created_at: Some("2026-01-01T00:00:00Z"),
            expires_at,
        },
    )
    .unwrap();
    let params = PublicKeyDocumentParams {
        member_handle: "test@example.com",
        keys,
        binding_claims: None,
        attestation,
        created_at: "2026-01-01T00:00:00Z",
        expires_at,
        sig_sk: &keypairs.sig_sk,
        debug: false,
    };
    let public_key = build_public_key(&params).unwrap();
    // Keep ssh_temp alive until public_key is built
    drop(ssh_temp);
    let kid = public_key.protected.kid.clone();
    (public_key, kid)
}

#[test]
fn test_enforce_recipient_key_not_expired_expired_fails() {
    let (public_key, _kid) = build_test_public_key("2020-01-01T00:00:00Z");
    let attested = verify_public_key_with_attestation_context(&public_key, false, "test").unwrap();
    let result = enforce_recipient_key_not_expired(&attested);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("expired"),
        "Error should mention expiry: {}",
        err_msg
    );
}

#[test]
fn test_build_public_key_expiry_warning_expired() {
    let (public_key, _kid) = build_test_public_key("2020-01-01T00:00:00Z");
    let attested = verify_public_key_with_attestation_context(&public_key, false, "test").unwrap();
    let result = build_public_key_expiry_warning(&attested).unwrap();
    assert!(result.is_some(), "Should return a warning for expired key");
    assert!(result.unwrap().contains("expired"));
}

#[test]
fn test_enforce_recipient_key_not_expired_valid() {
    let (public_key, _kid) = build_test_public_key("2099-12-31T23:59:59Z");
    let attested = verify_public_key_with_attestation_context(&public_key, false, "test").unwrap();
    assert!(enforce_recipient_key_not_expired(&attested).is_ok());
    assert!(build_public_key_expiry_warning(&attested)
        .unwrap()
        .is_none());
}

#[test]
fn test_enforce_recipient_key_not_expired_empty_expires_at() {
    let (public_key, _kid) = build_test_public_key("");
    let attested = verify_public_key_with_attestation_context(&public_key, false, "test").unwrap();
    assert!(enforce_recipient_key_not_expired(&attested).is_ok());
    assert!(build_public_key_expiry_warning(&attested)
        .unwrap()
        .is_none());
}

#[test]
fn test_build_loaded_verifying_key_valid() {
    let (public_key, kid) = build_test_public_key("2099-12-31T23:59:59Z");
    let result = build_loaded_verifying_key(
        &public_key,
        &kid,
        VerifyingKeySource::SignerPubEmbedded,
        "test",
        false,
    );
    assert!(result.is_ok());
    let loaded = result.unwrap();
    assert!(loaded.warnings.is_empty());
}

#[test]
fn test_verify_public_key_for_verification_exposes_signing_key_material() {
    let (public_key, _kid) = build_test_public_key("2099-12-31T23:59:59Z");

    let verified = verify_public_key_for_verification_context(&public_key, false, "test").unwrap();

    let expected_key: [u8; 32] =
        decode_base64url_nopad_array(&public_key.protected.keys.sig.x, "Ed25519 public key")
            .unwrap();
    assert_eq!(
        verified.verified_public_key.verifying_key().to_bytes(),
        expected_key
    );
    assert_eq!(
        verified.verified_public_key.document().protected.kid,
        public_key.protected.kid
    );
}

#[test]
fn test_build_loaded_verifying_key_expired_warning() {
    let (public_key, kid) = build_test_public_key("2020-01-01T00:00:00Z");
    let result = build_loaded_verifying_key(
        &public_key,
        &kid,
        VerifyingKeySource::SignerPubEmbedded,
        "test",
        false,
    );
    assert!(result.is_ok());
    let loaded = result.unwrap();
    assert!(!loaded.warnings.is_empty());
    assert!(loaded.warnings[0].contains("expired"));
}

#[test]
fn test_verify_recipient_public_keys_expired_fails() {
    let (public_key, _kid) = build_test_public_key("2020-01-01T00:00:00Z");
    let result = verify_recipient_public_keys(&[public_key], false);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("expired"),
        "Error should mention expiry: {}",
        err_msg
    );
}

#[test]
fn test_verify_recipient_public_keys_valid() {
    let (public_key, _kid) = build_test_public_key("2099-12-31T23:59:59Z");
    let result = verify_recipient_public_keys(&[public_key], false);
    assert!(result.is_ok());
}

#[test]
fn test_build_public_key_expiry_warning_expiring_soon() {
    let now = time::OffsetDateTime::now_utc();
    let future = now + time::Duration::days(15);
    let expires_at = future
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let (public_key, _kid) = build_test_public_key(&expires_at);
    let attested = verify_public_key_with_attestation_context(&public_key, false, "test").unwrap();
    let warning = build_public_key_expiry_warning(&attested).unwrap();
    assert!(warning.is_some(), "Should warn about expiring soon");
    assert!(
        warning.as_ref().unwrap().contains("expires in"),
        "Warning should mention 'expires in': {}",
        warning.unwrap()
    );
}

#[test]
fn test_build_recipient_key_expiry_warning_expiring_soon() {
    let now = time::OffsetDateTime::now_utc();
    let future = now + time::Duration::days(15);
    let expires_at = future
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let (public_key, _kid) = build_test_public_key(&expires_at);
    let attested = verify_public_key_with_attestation_context(&public_key, false, "test").unwrap();

    let warning = build_recipient_key_expiry_warning(&attested).unwrap();

    assert!(
        warning.is_some(),
        "Should warn about expiring soon recipient key"
    );
    assert!(
        warning
            .as_ref()
            .unwrap()
            .contains("Recipient public key for 'test@example.com' expires in"),
        "Warning should mention recipient expiry: {}",
        warning.unwrap()
    );
}

#[test]
fn test_build_recipient_key_expiry_warning_expired_none() {
    let (public_key, _kid) = build_test_public_key("2020-01-01T00:00:00Z");
    let attested = verify_public_key_with_attestation_context(&public_key, false, "test").unwrap();
    let warning = build_recipient_key_expiry_warning(&attested).unwrap();
    assert!(warning.is_none());
}
