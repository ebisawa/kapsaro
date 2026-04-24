// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for ArtifactSignature model

use crate::keygen_helpers::build_dummy_public_key;
use secretenv::model::signature::ArtifactSignature;

#[test]
fn test_signature_serialization() {
    let sig = ArtifactSignature {
        alg: secretenv::model::identifiers::alg::SIGNATURE_ED25519.to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        sig: "SGVsbG8gV29ybGQ".to_string(),
    };

    let json = serde_json::to_string(&sig).unwrap();
    assert!(json.contains(&format!(
        "\"alg\":\"{}\"",
        secretenv::model::identifiers::alg::SIGNATURE_ED25519
    )));
    assert!(!json.contains("\"signer\""));
    assert!(json.contains("\"kid\":\"7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD\""));
    assert!(json.contains("\"signer_pub\""));
    assert!(json.contains("\"sig\":\"SGVsbG8gV29ybGQ\""));
}

#[test]
fn test_signature_deserialization() {
    let json = r#"{
        "alg": "eddsa-ed25519",
        "kid": "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA",
        "signer_pub": {
            "protected": {
                "format": "secretenv.public.key@4",
                "member_id": "alice@example.com",
                "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "identity": {
                    "keys": {
                        "kem": { "kty": "OKP", "crv": "X25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
                        "sig": { "kty": "OKP", "crv": "Ed25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
                    },
                    "attestation": {
                        "method": "ssh-sign",
                        "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
                    }
                },
                "expires_at": "2027-01-01T00:00:00Z"
            },
            "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        },
        "sig": "YWJjZGVmZ2hp"
    }"#;

    let sig: ArtifactSignature = serde_json::from_str(json).unwrap();
    assert_eq!(
        sig.alg,
        secretenv::model::identifiers::alg::SIGNATURE_ED25519
    );
    assert_eq!(sig.kid, "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA");
    assert_eq!(sig.sig, "YWJjZGVmZ2hp");
    assert_eq!(sig.signer_pub.protected.member_id, "alice@example.com");
}

#[test]
fn test_signature_roundtrip() {
    let original = ArtifactSignature {
        alg: secretenv::model::identifiers::alg::SIGNATURE_ED25519.to_string(),
        kid: "RDKJ8YHMPPJHW7QC3446GPNXHNRTX61N".to_string(),
        signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        sig: "dGVzdHNpZ25hdHVyZQ".to_string(),
    };

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: ArtifactSignature = serde_json::from_str(&json).unwrap();

    assert_eq!(original, deserialized);
}
