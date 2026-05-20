// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH signature verification
//!
//! Tests for verify_sshsig validation logic

use ed25519_dalek::{Signer, SigningKey};
use secretenv_core::cli_api::test_support::domain::public_key::{IdentityKeys, JwkOkpPublicKey};
use secretenv_core::cli_api::test_support::helpers::codec::base64_public::{
    encode_base64_standard, encode_base64url_nopad,
};
use secretenv_core::cli_api::test_support::storage::ssh::external::traits::SshKeygen;
use secretenv_core::cli_api::test_support::storage::ssh::protocol::constants::ATTESTATION_NAMESPACE;
use secretenv_core::cli_api::test_support::storage::ssh::protocol::types::Ed25519RawSignature;
use secretenv_core::cli_api::test_support::storage::ssh::protocol::wire::encode_ssh_string;
use secretenv_core::cli_api::test_support::storage::ssh::verify::verify_sshsig;
use secretenv_core::cli_api::test_support::storage::ssh::verify::{
    build_attestation_signed_data, verify_attestation,
};
use std::path::Path;
use std::sync::Mutex;

const VALID_SIG: &str = "-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----";
const ED25519_KEY: &str = "ssh-ed25519 AAAA... comment";

/// Stub SshKeygen that always succeeds (validation tests never reach trait methods)
struct StubSshKeygen;

impl SshKeygen for StubSshKeygen {
    fn derive_public_key(&self, _key_path: &Path) -> secretenv_core::Result<String> {
        unimplemented!()
    }
    fn sign(
        &self,
        _key_path: &Path,
        _namespace: &str,
        _ssh_pubkey: &str,
        _data: &[u8],
    ) -> secretenv_core::Result<Ed25519RawSignature> {
        unimplemented!()
    }
    fn verify(
        &self,
        _ssh_pubkey: &str,
        _namespace: &str,
        _message: &[u8],
        _signature: &str,
    ) -> secretenv_core::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RecordedVerifyCall {
    ssh_pubkey: String,
    namespace: String,
    message: Vec<u8>,
    signature: String,
}

#[derive(Default)]
struct RecordingSshKeygen {
    call: Mutex<Option<RecordedVerifyCall>>,
}

impl SshKeygen for RecordingSshKeygen {
    fn derive_public_key(&self, _key_path: &Path) -> secretenv_core::Result<String> {
        unimplemented!()
    }

    fn sign(
        &self,
        _key_path: &Path,
        _namespace: &str,
        _ssh_pubkey: &str,
        _data: &[u8],
    ) -> secretenv_core::Result<Ed25519RawSignature> {
        unimplemented!()
    }

    fn verify(
        &self,
        ssh_pubkey: &str,
        namespace: &str,
        message: &[u8],
        signature: &str,
    ) -> secretenv_core::Result<()> {
        *self.call.lock().unwrap() = Some(RecordedVerifyCall {
            ssh_pubkey: ssh_pubkey.to_string(),
            namespace: namespace.to_string(),
            message: message.to_vec(),
            signature: signature.to_string(),
        });
        Ok(())
    }
}

#[test]
fn test_verify_sshsig_validation() {
    let keygen = StubSshKeygen;

    assert!(verify_sshsig(&keygen, "", b"msg", VALID_SIG)
        .unwrap_err()
        .to_string()
        .contains("empty"));

    assert!(verify_sshsig(&keygen, "ssh-rsa AAAA...", b"msg", VALID_SIG)
        .unwrap_err()
        .to_string()
        .contains(
            secretenv_core::cli_api::test_support::storage::ssh::protocol::constants::KEY_TYPE_ED25519
        ));

    assert!(verify_sshsig(&keygen, ED25519_KEY, b"msg", "")
        .unwrap_err()
        .to_string()
        .contains("empty"));

    assert!(verify_sshsig(&keygen, ED25519_KEY, b"msg", "invalid")
        .unwrap_err()
        .to_string()
        .contains("armored"));
}

#[test]
fn test_verify_sshsig_delegates_valid_input_to_keygen() {
    let keygen = RecordingSshKeygen::default();
    let message = b"attestation payload";

    verify_sshsig(&keygen, ED25519_KEY, message, VALID_SIG).unwrap();

    let call = keygen.call.lock().unwrap().take().expect("verify call");
    assert_eq!(call.ssh_pubkey, ED25519_KEY);
    assert_eq!(call.namespace, ATTESTATION_NAMESPACE);
    assert_eq!(call.message, message);
    assert_eq!(call.signature, VALID_SIG);
}

fn test_identity_keys() -> IdentityKeys {
    IdentityKeys {
        kem: JwkOkpPublicKey {
            kty: "OKP".to_string(),
            crv: "X25519".to_string(),
            x: encode_base64url_nopad(&[1u8; 32]),
        },
        sig: JwkOkpPublicKey {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: encode_base64url_nopad(&[2u8; 32]),
        },
    }
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn ssh_public_key_text(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let mut blob = Vec::new();
    blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519"));
    blob.extend_from_slice(&encode_ssh_string(verifying_key.as_bytes()));
    format!("ssh-ed25519 {} test-key", encode_base64_standard(&blob))
}

fn ssh_public_key_text_with_trailing_data(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let mut blob = Vec::new();
    blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519"));
    blob.extend_from_slice(&encode_ssh_string(verifying_key.as_bytes()));
    blob.push(1);
    format!("ssh-ed25519 {} test-key", encode_base64_standard(&blob))
}

fn sign_attestation(identity_keys: &IdentityKeys, signing_key: &SigningKey) -> String {
    let signed_data = build_attestation_signed_data(identity_keys).unwrap();
    let signature = signing_key.sign(&signed_data);
    encode_base64url_nopad(&signature.to_bytes())
}

#[test]
fn test_verify_attestation_raw_signature_success() {
    let identity_keys = test_identity_keys();
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text(&signing_key);
    let sig = sign_attestation(&identity_keys, &signing_key);

    verify_attestation(&identity_keys, &ssh_pubkey, &sig).unwrap();
}

#[test]
fn test_verify_attestation_rejects_public_key_blob_trailing_data() {
    let identity_keys = test_identity_keys();
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text_with_trailing_data(&signing_key);
    let sig = sign_attestation(&identity_keys, &signing_key);

    let error = verify_attestation(&identity_keys, &ssh_pubkey, &sig).unwrap_err();

    assert!(error.to_string().contains("unexpected trailing data"));
}

#[test]
fn test_verify_attestation_rejects_tampered_identity_keys() {
    let identity_keys = test_identity_keys();
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text(&signing_key);
    let sig = sign_attestation(&identity_keys, &signing_key);
    let mut tampered = identity_keys.clone();
    tampered.sig.x = encode_base64url_nopad(&[3u8; 32]);

    let error = verify_attestation(&tampered, &ssh_pubkey, &sig).unwrap_err();

    assert!(error.to_string().contains("verification failed"));
}

#[test]
fn test_verify_attestation_rejects_invalid_base64url_signature() {
    let identity_keys = test_identity_keys();
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text(&signing_key);

    let error = verify_attestation(&identity_keys, &ssh_pubkey, "*not-base64*").unwrap_err();

    assert!(error
        .to_string()
        .contains("Failed to decode attestation signature"));
}

#[test]
fn test_verify_attestation_rejects_invalid_ssh_public_key() {
    let identity_keys = test_identity_keys();
    let signing_key = test_signing_key();
    let sig = sign_attestation(&identity_keys, &signing_key);

    let error = verify_attestation(&identity_keys, "ssh-ed25519 not-base64", &sig).unwrap_err();

    assert!(error.to_string().contains("Failed to decode base64"));
}
