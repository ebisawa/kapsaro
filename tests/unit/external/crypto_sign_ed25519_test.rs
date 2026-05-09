// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for Ed25519 signature primitives

use ed25519_dalek::SigningKey;
use secretenv::crypto::sign::{sign_trust_store_bytes, verify_trust_store_bytes};
use secretenv::model::trust_store::TrustStoreSignature;
use secretenv::model::wire::alg::SIGNATURE_ED25519;

#[test]
fn test_sign_trust_store_bytes_returns_valid_structure() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);

    let canonical_bytes = b"test canonical bytes";

    let sig = sign_trust_store_bytes(
        canonical_bytes,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        SIGNATURE_ED25519,
    )
    .unwrap();

    assert_eq!(sig.alg, SIGNATURE_ED25519);
    assert_eq!(sig.kid, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    assert!(!sig.sig.is_empty());
}

#[test]
fn test_verify_trust_store_bytes_accepts_valid_signature() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let canonical_bytes = b"test canonical bytes";

    let sig = sign_trust_store_bytes(
        canonical_bytes,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        SIGNATURE_ED25519,
    )
    .unwrap();
    verify_trust_store_bytes(canonical_bytes, &vk, &sig, SIGNATURE_ED25519).unwrap();
}

#[test]
fn test_verify_trust_store_bytes_rejects_wrong_algorithm() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let canonical_bytes = b"test canonical bytes";

    let bad_sig = TrustStoreSignature {
        alg: "rsa-2048".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        sig: "AAAA".to_string(),
    };

    let result = verify_trust_store_bytes(canonical_bytes, &vk, &bad_sig, SIGNATURE_ED25519);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unsupported signature algorithm"));
}

#[test]
fn test_verify_trust_store_bytes_rejects_tampered_bytes() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let original = b"test canonical bytes";
    let tampered = b"tampered canonical bytes";

    let sig = sign_trust_store_bytes(
        original,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        SIGNATURE_ED25519,
    )
    .unwrap();

    let result = verify_trust_store_bytes(tampered, &vk, &sig, SIGNATURE_ED25519);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Cryptographic error: Signature verification failed"
    );
}

#[test]
fn test_sign_trust_store_bytes_deterministic() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);

    let canonical_bytes = b"deterministic test bytes";

    let sig1 = sign_trust_store_bytes(
        canonical_bytes,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        SIGNATURE_ED25519,
    )
    .unwrap();
    let sig2 = sign_trust_store_bytes(
        canonical_bytes,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        SIGNATURE_ED25519,
    )
    .unwrap();

    // Ed25519 signatures are deterministic per RFC 8032
    assert_eq!(sig1.sig, sig2.sig);
}

#[test]
fn test_sign_kv_returns_valid_structure() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);

    let canonical_bytes = b":SECRETENV_KV 5\n:WRAP {...}\nKEY {...}\n";

    let sig = sign_trust_store_bytes(
        canonical_bytes,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        SIGNATURE_ED25519,
    )
    .unwrap();

    assert_eq!(sig.alg, SIGNATURE_ED25519);
    assert_eq!(sig.kid, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    assert!(!sig.sig.is_empty());
}

#[test]
fn test_verify_kv_accepts_valid_signature() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let canonical_bytes = b":SECRETENV_KV 5\n:WRAP {...}\nKEY {...}\n";

    let sig = sign_trust_store_bytes(
        canonical_bytes,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        SIGNATURE_ED25519,
    )
    .unwrap();
    verify_trust_store_bytes(canonical_bytes, &vk, &sig, SIGNATURE_ED25519).unwrap();
}

#[test]
fn test_verify_kv_rejects_tampered_content() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let original = b":SECRETENV_KV 5\n:WRAP {...}\nKEY {...}\n";
    let tampered = b":SECRETENV_KV 5\n:WRAP {...}\nKEY {!!!}\n";

    let sig = sign_trust_store_bytes(
        original,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        SIGNATURE_ED25519,
    )
    .unwrap();
    let result = verify_trust_store_bytes(tampered, &vk, &sig, SIGNATURE_ED25519);

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Cryptographic error: Signature verification failed"
    );
}

#[test]
fn test_verify_trust_store_bytes_invalid_base64_error_message_sanitized() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let bad_sig = TrustStoreSignature {
        alg: SIGNATURE_ED25519.to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        sig: "*not-base64*".to_string(),
    };

    let result =
        verify_trust_store_bytes(b"test canonical bytes", &vk, &bad_sig, SIGNATURE_ED25519);

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Cryptographic error: Invalid signature Base64"
    );
}

#[test]
fn test_kv_lf_normalization_matters() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let lf_version = b":SECRETENV_KV 5\nKEY {...}\n";
    let crlf_version = b":SECRETENV_KV 5\r\nKEY {...}\r\n";

    // Sign LF version
    let sig = sign_trust_store_bytes(
        lf_version,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        SIGNATURE_ED25519,
    )
    .unwrap();

    // Verify with CRLF should fail (caller must normalize)
    let result = verify_trust_store_bytes(crlf_version, &vk, &sig, SIGNATURE_ED25519);
    assert!(result.is_err());
}
