// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for Ed25519 signature primitives

use ed25519_dalek::SigningKey;
use secretenv_core::cli_api::test_support::domain::trust_store::TrustStoreSignature;
use secretenv_core::cli_api::test_support::domain::wire::algorithm::SIGNATURE_ED25519;
use secretenv_core::cli_api::test_support::operations::trust::signature::sign_trust_store_bytes;
use secretenv_core::cli_api::test_support::operations::trust::verification::verify_trust_store_bytes;

#[test]
fn test_sign_trust_store_bytes_returns_valid_structure() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);

    let canonical_bytes = b"test canonical bytes";

    let sig =
        sign_trust_store_bytes(canonical_bytes, &sk, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();

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

    let sig =
        sign_trust_store_bytes(canonical_bytes, &sk, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();
    verify_trust_store_bytes(canonical_bytes, &vk, &sig).unwrap();
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

    let result = verify_trust_store_bytes(canonical_bytes, &vk, &bad_sig);
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

    let sig = sign_trust_store_bytes(original, &sk, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();

    let result = verify_trust_store_bytes(tampered, &vk, &sig);
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

    let sig1 =
        sign_trust_store_bytes(canonical_bytes, &sk, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();
    let sig2 =
        sign_trust_store_bytes(canonical_bytes, &sk, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();

    // Ed25519 signatures are deterministic per RFC 8032
    assert_eq!(sig1.sig, sig2.sig);
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

    let result = verify_trust_store_bytes(b"test canonical bytes", &vk, &bad_sig);

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

    let lf_version = b":SECRETENV_KV 9\nKEY {...}\n";
    let crlf_version = b":SECRETENV_KV 9\r\nKEY {...}\r\n";

    // Sign LF version
    let sig = sign_trust_store_bytes(lf_version, &sk, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();

    // Verify with CRLF should fail (caller must normalize)
    let result = verify_trust_store_bytes(crlf_version, &vk, &sig);
    assert!(result.is_err());
}
