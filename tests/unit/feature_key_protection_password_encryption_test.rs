// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use secretenv::feature::key::protection::password_encryption::{
    decrypt_private_key_with_password, encrypt_private_key_with_password,
};
use secretenv::model::private_key::{
    EncryptedData, IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyAlgorithm,
    PrivateKeyPlaintext, PrivateKeyProtected,
};
use secretenv::support::codec::base64_public::encode_base64url_nopad;

const TEST_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

fn b64(data: &[u8]) -> String {
    encode_base64url_nopad(data)
}

fn build_test_plaintext() -> PrivateKeyPlaintext {
    let kem_sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let kem_pk = x25519_dalek::PublicKey::from(&kem_sk);

    let sig_sk = SigningKey::generate(&mut OsRng);
    let sig_pk = ed25519_dalek::VerifyingKey::from(&sig_sk);

    PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: "X25519".to_string(),
                x: b64(kem_pk.as_bytes()),
                d: b64(&kem_sk.to_bytes()),
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                x: b64(&sig_pk.to_bytes()),
                d: b64(&sig_sk.to_bytes()),
            },
        },
    }
}

#[test]
fn test_password_encrypt_decrypt_roundtrip() {
    let plaintext = build_test_plaintext();
    let password = "test-password-42";

    let encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        TEST_KID,
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        password,
        false,
    )
    .expect("encryption should succeed");

    let decrypted = decrypt_private_key_with_password(&encrypted, password, false)
        .expect("decryption should succeed");

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_password_encrypt_wrong_password_fails() {
    let plaintext = build_test_plaintext();

    let encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        TEST_KID,
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        "correct-password",
        false,
    )
    .expect("encryption should succeed");

    let result = decrypt_private_key_with_password(&encrypted, "wrong-password", false);
    assert!(
        result.is_err(),
        "decryption with wrong password should fail"
    );
}

#[test]
fn test_password_encrypt_alg_kdf_is_argon2id() {
    let plaintext = build_test_plaintext();

    let encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        TEST_KID,
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        "test-password",
        false,
    )
    .expect("encryption should succeed");

    match &encrypted.protected.alg {
        PrivateKeyAlgorithm::Argon2id { aead, .. } => {
            assert_eq!(aead, "xchacha20-poly1305");
        }
        _ => panic!("expected Argon2id algorithm variant"),
    }

    // Verify kdf tag serializes correctly
    let json = serde_json::to_value(&encrypted.protected.alg).unwrap();
    assert_eq!(json["kdf"], "argon2id-hkdf-sha256");
}

#[test]
fn test_password_encrypt_preserves_metadata() {
    let plaintext = build_test_plaintext();
    let member_id = "bob@example.com";
    let kid = TEST_KID;
    let created_at = "2026-03-01T12:00:00Z";
    let expires_at = "2027-03-01T12:00:00Z";

    let encrypted = encrypt_private_key_with_password(
        &plaintext, member_id, kid, created_at, expires_at, "pw", false,
    )
    .expect("encryption should succeed");

    assert_eq!(encrypted.protected.member_id, member_id);
    assert_eq!(encrypted.protected.kid, kid);
    assert_eq!(encrypted.protected.created_at, created_at);
    assert_eq!(encrypted.protected.expires_at, expires_at);
    assert_eq!(encrypted.protected.format, "secretenv.private.key@4");
}

#[test]
fn test_password_decrypt_rejects_sshsig_key() {
    let private_key = PrivateKey {
        protected: PrivateKeyProtected {
            format: "secretenv.private.key@4".to_string(),
            member_id: "alice@example.com".to_string(),
            kid: TEST_KID.to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "SHA256:dummy".to_string(),
                salt: "AAAA".to_string(),
                aead: "xchacha20-poly1305".to_string(),
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
        },
        encrypted: EncryptedData {
            nonce: "AAAA".to_string(),
            ct: "AAAA".to_string(),
        },
    };

    let result = decrypt_private_key_with_password(&private_key, "test-password", false);
    assert!(result.is_err(), "SshSig key should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Argon2id") || err.contains("SSH"),
        "error should mention expected algorithm: {}",
        err
    );
}

#[test]
fn test_password_decrypt_rejects_unsupported_aead() {
    let plaintext = build_test_plaintext();
    let password = "test-password-42";

    let mut encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        TEST_KID,
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        password,
        false,
    )
    .expect("encryption should succeed");

    // Tamper with the AEAD field
    encrypted.protected.alg = match encrypted.protected.alg {
        PrivateKeyAlgorithm::Argon2id { salt, .. } => PrivateKeyAlgorithm::Argon2id {
            salt,
            aead: "aes-256-gcm".to_string(),
        },
        other => other,
    };

    let result = decrypt_private_key_with_password(&encrypted, password, false);
    assert!(result.is_err(), "unsupported AEAD should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("aes-256-gcm") && err.contains("xchacha20-poly1305"),
        "error should mention both expected and actual AEAD: {}",
        err
    );
}
