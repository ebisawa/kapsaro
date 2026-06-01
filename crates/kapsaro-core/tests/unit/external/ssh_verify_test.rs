// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH signature verification
//!
//! Tests for verify_sshsig validation logic

use ed25519_dalek::{Signer, SigningKey};
use kapsaro_core::cli_api::test_support::domain::public_key::{
    BindingClaims, GithubAccount, IdentityKeys, JwkOkpPublicKey,
};
use kapsaro_core::cli_api::test_support::helpers::codec::base64_public::{
    encode_base64_standard, encode_base64url_nopad,
};
use kapsaro_core::cli_api::test_support::storage::ssh::external::traits::SshKeygen;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::constants::ATTESTATION_NAMESPACE;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::types::Ed25519RawSignature;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::wire::encode_ssh_string;
use kapsaro_core::cli_api::test_support::storage::ssh::verify::verify_sshsig;
use kapsaro_core::cli_api::test_support::storage::ssh::verify::{
    build_attestation_signed_data, verify_attestation,
};
use kapsaro_core::cli_api::test_support::wire::public_key::AttestationBodyInput;
use std::path::Path;
use std::sync::Mutex;

const VALID_SIG: &str = "-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----";
const ED25519_KEY: &str = "ssh-ed25519 AAAA... comment";
const ATTESTATION_SUBJECT_HANDLE: &str = "alice@example.com";
const ATTESTATION_CREATED_AT: &str = "2026-01-01T00:00:00Z";
const ATTESTATION_EXPIRES_AT: &str = "2027-01-01T00:00:00Z";

/// Stub SshKeygen that always succeeds (validation tests never reach trait methods)
struct StubSshKeygen;

impl SshKeygen for StubSshKeygen {
    fn derive_public_key(&self, _key_path: &Path) -> kapsaro_core::Result<String> {
        unimplemented!()
    }
    fn sign(
        &self,
        _key_path: &Path,
        _namespace: &str,
        _ssh_pubkey: &str,
        _data: &[u8],
    ) -> kapsaro_core::Result<Ed25519RawSignature> {
        unimplemented!()
    }
    fn verify(
        &self,
        _ssh_pubkey: &str,
        _namespace: &str,
        _message: &[u8],
        _signature: &str,
    ) -> kapsaro_core::Result<()> {
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
    fn derive_public_key(&self, _key_path: &Path) -> kapsaro_core::Result<String> {
        unimplemented!()
    }

    fn sign(
        &self,
        _key_path: &Path,
        _namespace: &str,
        _ssh_pubkey: &str,
        _data: &[u8],
    ) -> kapsaro_core::Result<Ed25519RawSignature> {
        unimplemented!()
    }

    fn verify(
        &self,
        ssh_pubkey: &str,
        namespace: &str,
        message: &[u8],
        signature: &str,
    ) -> kapsaro_core::Result<()> {
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
            kapsaro_core::cli_api::test_support::storage::ssh::protocol::constants::KEY_TYPE_ED25519
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

fn test_attestation_input(keys: &IdentityKeys) -> AttestationBodyInput<'_> {
    AttestationBodyInput {
        subject_handle: ATTESTATION_SUBJECT_HANDLE,
        keys,
        binding_claims: None,
        created_at: Some(ATTESTATION_CREATED_AT),
        expires_at: ATTESTATION_EXPIRES_AT,
    }
}

fn test_binding_claims() -> BindingClaims {
    BindingClaims {
        github_account: Some(GithubAccount {
            id: 42,
            login: "alice".to_string(),
        }),
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

fn sign_attestation(input: &AttestationBodyInput<'_>, signing_key: &SigningKey) -> String {
    let signed_data = build_attestation_signed_data(input).unwrap();
    let signature = signing_key.sign(&signed_data);
    encode_base64url_nopad(&signature.to_bytes())
}

#[test]
fn test_verify_attestation_raw_signature_success() {
    let identity_keys = test_identity_keys();
    let input = test_attestation_input(&identity_keys);
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text(&signing_key);
    let sig = sign_attestation(&input, &signing_key);

    verify_attestation(&input, ATTESTATION_METHOD_SSH_SIGN, &ssh_pubkey, &sig).unwrap();
}

#[test]
fn test_verify_attestation_rejects_public_key_blob_trailing_data() {
    let identity_keys = test_identity_keys();
    let input = test_attestation_input(&identity_keys);
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text_with_trailing_data(&signing_key);
    let sig = sign_attestation(&input, &signing_key);

    let error =
        verify_attestation(&input, ATTESTATION_METHOD_SSH_SIGN, &ssh_pubkey, &sig).unwrap_err();

    assert!(error.to_string().contains("unexpected trailing data"));
}

#[test]
fn test_verify_attestation_rejects_tampered_identity_keys() {
    let identity_keys = test_identity_keys();
    let input = test_attestation_input(&identity_keys);
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text(&signing_key);
    let sig = sign_attestation(&input, &signing_key);
    let mut tampered = identity_keys.clone();
    tampered.sig.x = encode_base64url_nopad(&[3u8; 32]);
    let tampered_input = test_attestation_input(&tampered);

    let error = verify_attestation(
        &tampered_input,
        ATTESTATION_METHOD_SSH_SIGN,
        &ssh_pubkey,
        &sig,
    )
    .unwrap_err();

    assert!(error.to_string().contains("verification failed"));
}

#[test]
fn test_verify_attestation_rejects_tampered_subject_handle() {
    let identity_keys = test_identity_keys();
    let input = test_attestation_input(&identity_keys);
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text(&signing_key);
    let sig = sign_attestation(&input, &signing_key);
    let tampered = AttestationBodyInput {
        subject_handle: "mallory@example.com",
        ..input
    };

    let error =
        verify_attestation(&tampered, ATTESTATION_METHOD_SSH_SIGN, &ssh_pubkey, &sig).unwrap_err();

    assert!(error.to_string().contains("verification failed"));
}

#[test]
fn test_verify_attestation_rejects_tampered_binding_claims() {
    let identity_keys = test_identity_keys();
    let binding_claims = test_binding_claims();
    let input = AttestationBodyInput {
        subject_handle: ATTESTATION_SUBJECT_HANDLE,
        keys: &identity_keys,
        binding_claims: Some(&binding_claims),
        created_at: Some(ATTESTATION_CREATED_AT),
        expires_at: ATTESTATION_EXPIRES_AT,
    };
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text(&signing_key);
    let sig = sign_attestation(&input, &signing_key);
    let tampered_binding_claims = BindingClaims {
        github_account: Some(GithubAccount {
            id: 43,
            login: "mallory".to_string(),
        }),
    };
    let tampered = AttestationBodyInput {
        binding_claims: Some(&tampered_binding_claims),
        ..input
    };

    let error =
        verify_attestation(&tampered, ATTESTATION_METHOD_SSH_SIGN, &ssh_pubkey, &sig).unwrap_err();

    assert!(error.to_string().contains("verification failed"));
}

#[test]
fn test_verify_attestation_rejects_tampered_expires_at() {
    let identity_keys = test_identity_keys();
    let input = test_attestation_input(&identity_keys);
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text(&signing_key);
    let sig = sign_attestation(&input, &signing_key);
    let tampered = AttestationBodyInput {
        expires_at: "2028-01-01T00:00:00Z",
        ..input
    };

    let error =
        verify_attestation(&tampered, ATTESTATION_METHOD_SSH_SIGN, &ssh_pubkey, &sig).unwrap_err();

    assert!(error.to_string().contains("verification failed"));
}

#[test]
fn test_verify_attestation_rejects_unsupported_method() {
    let identity_keys = test_identity_keys();
    let input = test_attestation_input(&identity_keys);
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text(&signing_key);
    let sig = sign_attestation(&input, &signing_key);

    let error = verify_attestation(&input, "ssh", &ssh_pubkey, &sig).unwrap_err();

    assert!(error.to_string().contains("Unsupported attestation method"));
}

#[test]
fn test_verify_attestation_rejects_invalid_base64url_signature() {
    let identity_keys = test_identity_keys();
    let input = test_attestation_input(&identity_keys);
    let signing_key = test_signing_key();
    let ssh_pubkey = ssh_public_key_text(&signing_key);

    let error = verify_attestation(
        &input,
        ATTESTATION_METHOD_SSH_SIGN,
        &ssh_pubkey,
        "*not-base64*",
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("Failed to decode attestation signature"));
}

#[test]
fn test_verify_attestation_rejects_invalid_ssh_public_key() {
    let identity_keys = test_identity_keys();
    let input = test_attestation_input(&identity_keys);
    let signing_key = test_signing_key();
    let sig = sign_attestation(&input, &signing_key);

    let error = verify_attestation(
        &input,
        ATTESTATION_METHOD_SSH_SIGN,
        "ssh-ed25519 not-base64",
        &sig,
    )
    .unwrap_err();

    assert!(error.to_string().contains("Failed to decode base64"));
}
