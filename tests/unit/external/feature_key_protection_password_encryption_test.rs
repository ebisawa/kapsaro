// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::crypto::aead::xchacha;
use secretenv::crypto::types::data::Plaintext;
use secretenv::crypto::types::primitives::{HkdfSalt, PrivateKeyIkmSalt};
use secretenv::feature::key::material::{build_private_key_plaintext, generate_keypairs};
use secretenv::feature::key::protection::binding::build_private_key_aad;
use secretenv::feature::key::protection::password_encryption::{
    decrypt_private_key_with_password, encrypt_private_key_with_password,
};
use secretenv::feature::key::protection::password_key_derivation::derive_key_from_password;
use secretenv::model::identifiers::{alg, format};
use secretenv::model::private_key::{
    PrivateKey, PrivateKeyAlgorithm, PrivateKeyEncData, PrivateKeyPlaintext, PrivateKeyProtected,
};
use secretenv::support::codec::base64_public::encode_base64url_nopad;
use secretenv::support::secret::SecretString;
use std::collections::BTreeSet;

const TEST_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

fn build_test_plaintext() -> PrivateKeyPlaintext {
    let keypairs = generate_keypairs().unwrap();
    build_private_key_plaintext(
        &keypairs.kem_sk,
        &keypairs.kem_pk,
        &keypairs.sig_sk,
        &keypairs.sig_pk,
    )
}

fn secret(value: &str) -> SecretString {
    SecretString::new(value.to_string())
}

fn build_password_private_key_with_plaintext_json(
    plaintext_json: &[u8],
    password: &SecretString,
) -> PrivateKey {
    let ikm_salt = PrivateKeyIkmSalt::new([7u8; 32]);
    let hkdf_salt = HkdfSalt::new([8u8; 32]);
    let protected = PrivateKeyProtected {
        format: format::PRIVATE_KEY_V6.to_string(),
        subject_handle: "alice@example.com".to_string(),
        kid: TEST_KID.to_string(),
        alg: PrivateKeyAlgorithm::Argon2id {
            ikm_salt: encode_base64url_nopad(ikm_salt.as_bytes()),
            hkdf_salt: encode_base64url_nopad(hkdf_salt.as_bytes()),
            aead: alg::AEAD_XCHACHA20_POLY1305.to_string(),
        },
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
    };
    let enc_key =
        derive_key_from_password(password, &ikm_salt, &hkdf_salt, TEST_KID, false).unwrap();
    let aad = build_private_key_aad(&protected).unwrap();
    let plaintext = Plaintext::from(plaintext_json.to_vec());
    let (ct, nonce) = xchacha::encrypt_with_nonce(&enc_key, &plaintext, &aad).unwrap();

    PrivateKey {
        protected,
        encrypted: PrivateKeyEncData {
            nonce: encode_base64url_nopad(nonce.as_bytes()),
            ct: encode_base64url_nopad(ct.as_bytes()),
        },
    }
}

#[test]
fn test_password_encrypt_decrypt_roundtrip() {
    let plaintext = build_test_plaintext();
    let password = secret("test-password-42");

    let encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        TEST_KID,
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &password,
        false,
    )
    .expect("encryption should succeed");

    let decrypted = decrypt_private_key_with_password(&encrypted, &password, false)
        .expect("decryption should succeed");

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_password_encrypt_wrong_password_fails() {
    let plaintext = build_test_plaintext();

    let correct_password = secret("correct-password");
    let encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        TEST_KID,
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &correct_password,
        false,
    )
    .expect("encryption should succeed");

    let wrong_password = secret("wrong-password");
    let result = decrypt_private_key_with_password(&encrypted, &wrong_password, false);
    let err = result.expect_err("decryption with wrong password should fail");
    assert_eq!(
        err.format_user_message(),
        "E_PRIVATE_KEY_DECRYPT_FAILED: private key decryption failed"
    );
}

#[test]
fn test_password_decrypt_sanitizes_plaintext_deserialize_error() {
    let password = secret("test-password-42");
    let private_key = build_password_private_key_with_plaintext_json(b"{", &password);

    let err = decrypt_private_key_with_password(&private_key, &password, false)
        .expect_err("invalid plaintext JSON should fail");

    assert_eq!(
        err.format_user_message(),
        "E_PRIVATE_KEY_DECRYPT_FAILED: private key decryption failed"
    );
    assert!(
        !crate::test_utils::error_chain_contains_serde_json(&err),
        "serde_json::Error must not remain in the source chain"
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
        &secret("test-password"),
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
    assert_eq!(json["kdf"], "argon2id-m64t3p4-hkdf-sha256");
}

#[test]
fn test_password_encrypt_preserves_metadata() {
    let plaintext = build_test_plaintext();
    let member_handle = "bob@example.com";
    let kid = TEST_KID;
    let created_at = "2026-03-01T12:00:00Z";
    let expires_at = "2027-03-01T12:00:00Z";

    let encrypted = encrypt_private_key_with_password(
        &plaintext,
        member_handle,
        kid,
        created_at,
        expires_at,
        &secret("pw"),
        false,
    )
    .expect("encryption should succeed");

    assert_eq!(encrypted.protected.subject_handle, member_handle);
    assert_eq!(encrypted.protected.kid, kid);
    assert_eq!(encrypted.protected.created_at, created_at);
    assert_eq!(encrypted.protected.expires_at, expires_at);
    assert_eq!(encrypted.protected.format, format::PRIVATE_KEY_V6);
}

#[test]
fn test_password_encrypt_protected_algorithm_shape() {
    let plaintext = build_test_plaintext();

    let encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        TEST_KID,
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &secret("test-password"),
        false,
    )
    .expect("encryption should succeed");

    let value = serde_json::to_value(&encrypted.protected.alg).unwrap();
    let object = value.as_object().unwrap();
    let fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();

    assert_eq!(
        fields,
        BTreeSet::from(["aead", "hkdf_salt", "ikm_salt", "kdf"])
    );
    assert_eq!(object["kdf"], "argon2id-m64t3p4-hkdf-sha256");
    assert_eq!(object["aead"], alg::AEAD_XCHACHA20_POLY1305);
}

#[test]
fn test_password_decrypt_rejects_sshsig_key() {
    let private_key = PrivateKey {
        protected: PrivateKeyProtected {
            format: format::PRIVATE_KEY_V6.to_string(),
            subject_handle: "alice@example.com".to_string(),
            kid: TEST_KID.to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "SHA256:dummy".to_string(),
                ikm_salt: encode_base64url_nopad(&[0u8; 32]),
                hkdf_salt: encode_base64url_nopad(&[1u8; 32]),
                aead: "xchacha20-poly1305".to_string(),
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
        },
        encrypted: PrivateKeyEncData {
            nonce: "AAAA".to_string(),
            ct: "AAAA".to_string(),
        },
    };

    let result = decrypt_private_key_with_password(&private_key, &secret("test-password"), false);
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
    let password = secret("test-password-42");

    let mut encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        TEST_KID,
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &password,
        false,
    )
    .expect("encryption should succeed");

    // Tamper with the AEAD field
    encrypted.protected.alg = match encrypted.protected.alg {
        PrivateKeyAlgorithm::Argon2id {
            ikm_salt,
            hkdf_salt,
            ..
        } => PrivateKeyAlgorithm::Argon2id {
            ikm_salt,
            hkdf_salt,
            aead: "aes-256-gcm".to_string(),
        },
        other => other,
    };

    let result = decrypt_private_key_with_password(&encrypted, &password, false);
    assert!(result.is_err(), "unsupported AEAD should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("aes-256-gcm") && err.contains("xchacha20-poly1305"),
        "error should mention both expected and actual AEAD: {}",
        err
    );
}
