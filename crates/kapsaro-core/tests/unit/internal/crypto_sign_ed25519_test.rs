// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for Ed25519 signature primitives

use crate::crypto::sign::{sign_detached_bytes, verify_detached_bytes};
use crate::feature::trust::signature::sign_trust_store_bytes;
use crate::feature::trust::verification::verify_trust_store_bytes;
use crate::model::trust_store::TrustStoreSignature;
use crate::model::wire::algorithm::SIGNATURE_ED25519;
use ed25519_dalek::{SigningKey, VerifyingKey};

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

    let lf_version = b":KAPSARO_KV 1\nKEY {...}\n";
    let crlf_version = b":KAPSARO_KV 1\r\nKEY {...}\r\n";

    // Sign LF version
    let sig = sign_trust_store_bytes(lf_version, &sk, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();

    // Verify with CRLF should fail (caller must normalize)
    let result = verify_trust_store_bytes(crlf_version, &vk, &sig);
    assert!(result.is_err());
}

#[test]
fn test_sign_detached_bytes_returns_raw_ed25519_signature_bytes() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);

    let signature = sign_detached_bytes(b"raw signature input", &sk).unwrap();

    assert_eq!(signature.len(), 64);
}

#[test]
fn test_verify_detached_bytes_accepts_raw_ed25519_signature_bytes() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let message = b"raw signature input";
    let signature = sign_detached_bytes(message, &sk).unwrap();

    verify_detached_bytes(message, &vk, &signature).unwrap();
}

/// RFC 8032 section 7.1 test vectors: (secret seed, public key, message, signature).
const RFC8032_VECTORS: &[(&str, &str, &str, &str)] = &[
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        concat!(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ),
];

/// Ties the signature bytes to the published vectors, so a change in framing or
/// encoding is caught rather than left to a round trip that agrees with itself.
#[test]
fn test_sign_detached_bytes_matches_the_rfc8032_vectors() {
    for (seed, public, message, signature) in RFC8032_VECTORS {
        let sk = SigningKey::from_bytes(&hex_array(seed));
        let message = hex::decode(message).unwrap();

        assert_eq!(hex::encode(sk.verifying_key().to_bytes()), *public);
        assert_eq!(
            hex::encode(sign_detached_bytes(&message, &sk).unwrap()),
            *signature,
        );
    }
}

#[test]
fn test_verify_detached_bytes_accepts_the_rfc8032_vectors() {
    for (_seed, public, message, signature) in RFC8032_VECTORS {
        let vk = VerifyingKey::from_bytes(&hex_array(public)).unwrap();
        let message = hex::decode(message).unwrap();

        verify_detached_bytes(&message, &vk, &hex::decode(signature).unwrap()).unwrap();
    }
}

fn hex_array(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

/// Compressed encoding of the Ed25519 identity point, which has order 1.
const SMALL_ORDER_POINT: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    bytes
};

/// A small-order verifying key makes `[k]A` the identity for every message, so
/// the verification equation collapses to `[S]B = R` and stops depending on the
/// message at all. Strict verification rejects the key instead.
#[test]
fn test_verify_detached_bytes_rejects_small_order_verifying_key() {
    let vk = VerifyingKey::from_bytes(&SMALL_ORDER_POINT).unwrap();
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&SMALL_ORDER_POINT);

    for message in [b"first artifact".as_slice(), b"second artifact".as_slice()] {
        assert!(verify_detached_bytes(message, &vk, &signature).is_err());
    }
}

/// A small-order `R` point lets a signature carry over between messages even
/// when the verifying key itself is well formed.
#[test]
fn test_verify_detached_bytes_rejects_small_order_signature_point() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let vk = sk.verifying_key();
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&SMALL_ORDER_POINT);

    assert!(verify_detached_bytes(b"raw signature input", &vk, &signature).is_err());
}
