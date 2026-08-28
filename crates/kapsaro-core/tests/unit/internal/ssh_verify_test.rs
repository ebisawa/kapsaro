// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for PublicKey attestation verification.
//!
//! Covers the signed data construction and rejection of tampered fields.

use crate::format::codec::base64_public::encode_base64url_nopad;
use crate::format::codec::codec_base64_fixtures::encode_base64_standard;
use crate::format::public_key::AttestationBodyInput;
use crate::io::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN;
use crate::io::ssh::protocol::wire::encode_ssh_string;
use crate::io::ssh::verify::{build_attestation_signed_data, verify_attestation};
use crate::model::public_key::{BindingClaims, GithubAccount, IdentityKeys, JwkOkpPublicKey};
use ed25519_dalek::{Signer, SigningKey};

const ATTESTATION_SUBJECT_HANDLE: &str = "alice@example.com";
const ATTESTATION_CREATED_AT: &str = "2026-01-01T00:00:00Z";
const ATTESTATION_EXPIRES_AT: &str = "2027-01-01T00:00:00Z";

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
    blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519").unwrap());
    blob.extend_from_slice(&encode_ssh_string(verifying_key.as_bytes()).unwrap());
    format!("ssh-ed25519 {} test-key", encode_base64_standard(&blob))
}

fn ssh_public_key_text_with_trailing_data(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let mut blob = Vec::new();
    blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519").unwrap());
    blob.extend_from_slice(&encode_ssh_string(verifying_key.as_bytes()).unwrap());
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
