// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::crypto::kdf::expand_to_array;
use secretenv::crypto::types::data::{Ikm, Info};
use secretenv::crypto::types::keys::XChaChaKey;
use secretenv::crypto::types::primitives::HkdfSalt;
use secretenv::feature::key::protection::encryption::{
    decrypt_private_key, encrypt_private_key, PrivateKeyEncryptionParams,
};
use secretenv::feature::key::protection::key_derivation::build_sign_message;
use secretenv::io::ssh::backend::signature_backend::SignatureBackend;
use secretenv::io::ssh::protocol::fingerprint::build_sha256_fingerprint;
use secretenv::io::ssh::protocol::types::Ed25519RawSignature;
use secretenv::model::identifiers::context::{
    SSH_KEY_PROTECTION_SIGN_MESSAGE_PREFIX_V5, SSH_PRIVATE_KEY_ENC_INFO_PREFIX_V5,
};
use secretenv::model::private_key::{IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKeyPlaintext};
use secretenv::support::codec::base64_public::encode_base64url_nopad;
use std::cell::Cell;

const TEST_SSH_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";
const OTHER_SSH_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT test-key-1";

fn build_test_plaintext() -> PrivateKeyPlaintext {
    let b64 = |data: &[u8]| encode_base64url_nopad(data);
    PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
                x: b64(&[2u8; 32]),
                d: b64(&[1u8; 32]),
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
                x: b64(&[4u8; 32]),
                d: b64(&[3u8; 32]),
            },
        },
    }
}

fn derive_enc_key(raw_sig: &[u8], salt: &HkdfSalt, kid: &str) -> secretenv::Result<XChaChaKey> {
    let ikm = Ikm::from(raw_sig);
    let info = Info::from_string(&format!("{}:{}", SSH_PRIVATE_KEY_ENC_INFO_PREFIX_V5, kid));
    let cek = expand_to_array(&ikm, Some(salt), &info)?;
    XChaChaKey::from_slice(cek.as_bytes())
}

#[test]
fn test_build_sign_message() {
    let ikm_salt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let message = build_sign_message(ikm_salt);

    assert!(message.starts_with(&format!("{}\n", SSH_KEY_PROTECTION_SIGN_MESSAGE_PREFIX_V5)));
    assert!(message.ends_with(ikm_salt));
}

#[test]
fn test_build_sign_message_format() {
    let ikm_salt = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    let message = build_sign_message(ikm_salt);

    let expected = format!(
        "{}\n{}",
        SSH_KEY_PROTECTION_SIGN_MESSAGE_PREFIX_V5, ikm_salt
    );

    assert_eq!(message, expected);
}

#[test]
fn test_derive_enc_key() {
    // Test key derivation from signature
    let raw_sig = [0u8; 64]; // Simulated Ed25519 signature
    let salt = HkdfSalt::new([1u8; 32]);
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let enc_key = derive_enc_key(&raw_sig, &salt, kid).unwrap();

    // Should be 32 bytes
    assert_eq!(enc_key.as_bytes().len(), 32);

    // Should be deterministic
    let enc_key2 = derive_enc_key(&raw_sig, &salt, kid).unwrap();
    assert_eq!(enc_key.as_bytes(), enc_key2.as_bytes());
}

#[test]
fn test_derive_enc_key_different_inputs() {
    // Different inputs should produce different keys
    let raw_sig = [0u8; 64];
    let salt = HkdfSalt::new([1u8; 32]);
    let kid1 = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let kid2 = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE";

    let key1 = derive_enc_key(&raw_sig, &salt, kid1).unwrap();
    let key2 = derive_enc_key(&raw_sig, &salt, kid2).unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_derive_enc_key_info_format() {
    // Verify the info string format
    let raw_sig = [0u8; 64];
    let salt = HkdfSalt::new([1u8; 32]);
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    // This should not panic
    derive_enc_key(&raw_sig, &salt, kid).unwrap();

    // The info should be "secretenv:sshsig-private-key-enc@5:{kid}"
    // We can't directly test the internal info, but we can verify it's consistent
}

#[test]
fn test_encrypt_decrypt_private_key_roundtrip_with_deterministic_backend() {
    // Deterministic backend avoids ssh-agent / ssh-keygen and user interaction.
    struct DeterministicBackend;
    impl SignatureBackend for DeterministicBackend {
        fn sign_for_ikm(
            &self,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv::Result<Ed25519RawSignature> {
            Ok(Ed25519RawSignature::new([0xAB; 64]))
        }
    }

    let plaintext = build_test_plaintext();

    let member_id = "alice";
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE";
    let ssh_pubkey = TEST_SSH_PUBKEY;
    let ssh_fpr = build_sha256_fingerprint(ssh_pubkey).unwrap();
    let created_at = "2026-01-01T00:00:00Z";
    let expires_at = "2027-01-01T00:00:00Z";

    let backend = DeterministicBackend;

    let encrypted = encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        backend: &backend,
        ssh_pubkey,
        ssh_fpr: ssh_fpr.to_string(),
        created_at: created_at.to_string(),
        expires_at: expires_at.to_string(),
        debug: false,
    })
    .expect("encrypt_private_key should succeed");

    let decrypted = decrypt_private_key(&encrypted, &backend, ssh_pubkey, false)
        .expect("decrypt_private_key should succeed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_decrypt_private_key_rejects_fingerprint_mismatch_before_kdf() {
    struct CountingBackend {
        calls: Cell<u32>,
    }

    impl SignatureBackend for CountingBackend {
        fn sign_for_ikm(
            &self,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv::Result<Ed25519RawSignature> {
            self.calls.set(self.calls.get() + 1);
            Ok(Ed25519RawSignature::new([0xCD; 64]))
        }
    }

    let plaintext = build_test_plaintext();

    let backend = CountingBackend {
        calls: Cell::new(0),
    };
    let encrypted = encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_id: "alice".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string(),
        backend: &backend,
        ssh_pubkey: TEST_SSH_PUBKEY,
        ssh_fpr: build_sha256_fingerprint(TEST_SSH_PUBKEY).unwrap(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        debug: false,
    })
    .unwrap();

    let err = decrypt_private_key(&encrypted, &backend, OTHER_SSH_PUBKEY, false).unwrap_err();
    let err_msg = err.to_string();
    let expected = build_sha256_fingerprint(TEST_SSH_PUBKEY).unwrap();
    let actual = build_sha256_fingerprint(OTHER_SSH_PUBKEY).unwrap();

    assert_eq!(backend.calls.get(), 2, "encrypt path should sign twice");
    assert!(
        err_msg.contains("E_PRIVATE_KEY_DECRYPT_FAILED"),
        "error should use private key decrypt failure code: {err_msg}"
    );
    assert!(
        err_msg.contains(&expected),
        "error should contain expected fingerprint: {err_msg}"
    );
    assert!(
        err_msg.contains(&actual),
        "error should contain actual fingerprint: {err_msg}"
    );
    assert_eq!(
        backend.calls.get(),
        2,
        "decrypt path must not call the backend when fingerprint mismatches"
    );
}

#[test]
fn test_decrypt_private_key_accepts_lowercase_fpr_prefix_roundtrip() {
    struct DeterministicBackend;
    impl SignatureBackend for DeterministicBackend {
        fn sign_for_ikm(
            &self,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv::Result<Ed25519RawSignature> {
            Ok(Ed25519RawSignature::new([0xAB; 64]))
        }
    }

    let plaintext = build_test_plaintext();

    let backend = DeterministicBackend;
    let ssh_fpr = build_sha256_fingerprint(TEST_SSH_PUBKEY).unwrap().replacen(
        "SHA256:",
        &"SHA256:".to_ascii_lowercase(),
        1,
    );
    let encrypted = encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_id: "alice".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string(),
        backend: &backend,
        ssh_pubkey: TEST_SSH_PUBKEY,
        ssh_fpr,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        debug: false,
    })
    .unwrap();

    let decrypted = decrypt_private_key(&encrypted, &backend, TEST_SSH_PUBKEY, false).unwrap();
    assert_eq!(decrypted, plaintext);
}
