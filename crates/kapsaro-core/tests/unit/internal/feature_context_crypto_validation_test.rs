// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Validation tests for feature::context::crypto module
//!
//! Tests for private key material validation helpers.

use crate::crypto::kem::{derive_public_key_from_secret, generate_keypair, X25519SecretKey};
use crate::feature::key::material::{
    validate_ed25519_consistency, validate_okp_key, validate_x25519_consistency,
};
use crate::format::codec::base64_public::encode_base64url_nopad;
use crate::support::secret::SecretArray;
use ed25519_dalek::SigningKey;

// ============================================================================
// validate_okp_key tests
// ============================================================================

#[test]
fn test_validate_okp_key_wrong_kty() {
    let d = encode_base64url_nopad(&[0u8; 32]);
    let x = encode_base64url_nopad(&[1u8; 32]);
    let result = validate_okp_key("RSA", "Ed25519", "Ed25519", &d, &x, "Sig");
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("Invalid Sig key type"), "got: {msg}");
}

#[test]
fn test_validate_okp_key_wrong_crv() {
    let d = encode_base64url_nopad(&[0u8; 32]);
    let x = encode_base64url_nopad(&[1u8; 32]);
    let result = validate_okp_key("OKP", "P-256", "Ed25519", &d, &x, "Sig");
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("Invalid Sig curve"), "got: {msg}");
}

#[test]
fn test_validate_okp_key_wrong_d_length() {
    let d = encode_base64url_nopad(&[0u8; 16]); // 16 bytes instead of 32
    let x = encode_base64url_nopad(&[1u8; 32]);
    let result = validate_okp_key("OKP", "Ed25519", "Ed25519", &d, &x, "Sig");
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("Invalid Sig private key length"), "got: {msg}");
}

#[test]
fn test_validate_okp_key_wrong_x_length() {
    let d = encode_base64url_nopad(&[0u8; 32]);
    let x = encode_base64url_nopad(&[1u8; 16]); // 16 bytes instead of 32
    let result = validate_okp_key("OKP", "Ed25519", "Ed25519", &d, &x, "Sig");
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("Invalid Sig public key length"), "got: {msg}");
}

#[test]
fn test_validate_okp_key() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let d = encode_base64url_nopad(signing_key.as_bytes());
    let x = encode_base64url_nopad(verifying_key.as_bytes());

    let result = validate_okp_key("OKP", "Ed25519", "Ed25519", &d, &x, "Sig");
    assert!(result.is_ok());
    let (d_bytes, x_bytes) = result.unwrap();
    assert_eq!(d_bytes.len(), 32);
    assert_eq!(x_bytes.len(), 32);
}

// ============================================================================
// validate_ed25519_consistency tests
// ============================================================================

#[test]
fn test_validate_ed25519_consistency_mismatch() {
    let d_bytes = SecretArray::new([42u8; 32]);
    // Use a different public key that doesn't match the private key
    let wrong_x_bytes = [0u8; 32];
    let result = validate_ed25519_consistency(&d_bytes, &wrong_x_bytes);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("key pair inconsistency"), "got: {msg}");
}

#[test]
fn test_validate_ed25519_consistency() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let d_bytes = SecretArray::new(*signing_key.as_bytes());
    let x_bytes = verifying_key.as_bytes();

    let result = validate_ed25519_consistency(&d_bytes, x_bytes);
    assert!(result.is_ok());
}

#[test]
fn test_validate_x25519_consistency_mismatch() {
    let secret = X25519SecretKey::from_bytes([1u8; 32]);
    let public = derive_public_key_from_secret(&secret).unwrap();
    let wrong_secret = X25519SecretKey::from_bytes([7u8; 32]);
    assert_ne!(wrong_secret.as_bytes(), secret.as_bytes());

    let d_bytes = SecretArray::new(*wrong_secret.as_bytes());
    let result = validate_x25519_consistency(&d_bytes, public.as_bytes());
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("key pair inconsistency"), "got: {msg}");
}

#[test]
fn test_validate_x25519_consistency() {
    let (secret, public) = generate_keypair().unwrap();
    let d_bytes = SecretArray::new(*secret.as_bytes());

    let result = validate_x25519_consistency(&d_bytes, public.as_bytes());
    assert!(result.is_ok());
}
