// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv_core::cli_api::test_support::domain::private_key::{
    IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyAlgorithm, PrivateKeyEncData,
    PrivateKeyPlaintext, PrivateKeyProtected,
};
use secretenv_core::cli_api::test_support::domain::wire::{
    algorithm,
    context::{HKDF_INFO_PRIVATE_KEY_SSHSIG_V7, SSHSIG_MESSAGE_PREFIX_PRIVATE_KEY_PROTECTION_V7},
    format,
};
use secretenv_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;
use secretenv_core::cli_api::test_support::operations::key::protection::binding::build_private_key_aad;
use secretenv_core::cli_api::test_support::operations::key::protection::encryption::{
    decrypt_private_key, encrypt_private_key, PrivateKeyEncryptionParams,
};
use secretenv_core::cli_api::test_support::operations::key::protection::key_derivation::build_sign_message;
use secretenv_core::cli_api::test_support::primitives::aead::xchacha;
use secretenv_core::cli_api::test_support::primitives::kdf::expand_to_array;
use secretenv_core::cli_api::test_support::primitives::types::data::{Ikm, Info, Plaintext};
use secretenv_core::cli_api::test_support::primitives::types::keys::XChaChaKey;
use secretenv_core::cli_api::test_support::primitives::types::primitives::{
    HkdfSalt, PrivateKeyIkmSalt,
};
use secretenv_core::cli_api::test_support::storage::ssh::backend::signature_backend::SignatureBackend;
use secretenv_core::cli_api::test_support::storage::ssh::protocol::fingerprint::build_sha256_fingerprint;
use secretenv_core::cli_api::test_support::storage::ssh::protocol::types::Ed25519RawSignature;
use std::cell::Cell;
use std::collections::BTreeSet;

const TEST_SSH_PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";
const OTHER_SSH_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT test-key-1";

fn build_test_plaintext() -> PrivateKeyPlaintext {
    let b64 = |data: &[u8]| encode_base64url_nopad(data);
    PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_X25519
                    .to_string(),
                x: b64(&[2u8; 32]),
                d: b64(&[1u8; 32]),
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_ED25519
                    .to_string(),
                x: b64(&[4u8; 32]),
                d: b64(&[3u8; 32]),
            },
        },
    }
}

fn derive_enc_key(
    raw_sig: &[u8],
    salt: &HkdfSalt,
    kid: &str,
) -> secretenv_core::Result<XChaChaKey> {
    let ikm = Ikm::from(raw_sig);
    let info = Info::from_string(&format!("{}:{}", HKDF_INFO_PRIVATE_KEY_SSHSIG_V7, kid));
    let cek = expand_to_array(&ikm, Some(salt), &info)?;
    XChaChaKey::from_slice(cek.as_bytes())
}

fn tamper_base64url(input: &str) -> String {
    let mut chars: Vec<char> = input.chars().collect();
    let first = chars.first_mut().expect("base64url must be non-empty");
    *first = if *first == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

fn build_ssh_private_key_with_plaintext_json(plaintext_json: &[u8]) -> PrivateKey {
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE";
    let ikm_salt = PrivateKeyIkmSalt::new([9u8; 32]);
    let hkdf_salt = HkdfSalt::new([10u8; 32]);
    let protected = PrivateKeyProtected {
        format: format::PRIVATE_KEY_V7.to_string(),
        subject_handle: "alice".to_string(),
        kid: kid.to_string(),
        alg: PrivateKeyAlgorithm::SshSig {
            fpr: build_sha256_fingerprint(TEST_SSH_PUBKEY).unwrap(),
            ikm_salt: encode_base64url_nopad(ikm_salt.as_bytes()),
            hkdf_salt: encode_base64url_nopad(hkdf_salt.as_bytes()),
            aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
        },
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
    };
    let enc_key = derive_enc_key(&[0xAB; 64], &hkdf_salt, kid).unwrap();
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
fn test_build_sign_message() {
    let ikm_salt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let message = build_sign_message(ikm_salt);

    assert!(message.starts_with(&format!(
        "{}\n",
        SSHSIG_MESSAGE_PREFIX_PRIVATE_KEY_PROTECTION_V7
    )));
    assert!(message.ends_with(ikm_salt));
}

#[test]
fn test_build_sign_message_format() {
    let ikm_salt = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    let message = build_sign_message(ikm_salt);

    let expected = format!(
        "{}\n{}",
        SSHSIG_MESSAGE_PREFIX_PRIVATE_KEY_PROTECTION_V7, ikm_salt
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
    struct CountingBackend {
        calls: Cell<u32>,
    }

    impl SignatureBackend for CountingBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
            self.calls.set(self.calls.get() + 1);
            Ok(Ed25519RawSignature::new([0xAB; 64]))
        }
    }

    let plaintext = build_test_plaintext();

    let member_handle = "alice";
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE";
    let ssh_pubkey = TEST_SSH_PUBKEY;
    let ssh_fpr = build_sha256_fingerprint(ssh_pubkey).unwrap();
    let created_at = "2026-01-01T00:00:00Z";
    let expires_at = "2027-01-01T00:00:00Z";

    let backend = CountingBackend {
        calls: Cell::new(0),
    };

    let encrypted = encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_handle: member_handle.to_string(),
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
    assert_eq!(
        backend.calls.get(),
        3,
        "encrypt uses 2 signatures, decrypt uses 1"
    );
}

#[test]
fn test_encrypt_private_key_protected_algorithm_shape() {
    struct DeterministicBackend;

    impl SignatureBackend for DeterministicBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
            Ok(Ed25519RawSignature::new([0xAB; 64]))
        }
    }

    let plaintext = build_test_plaintext();
    let ssh_fpr = build_sha256_fingerprint(TEST_SSH_PUBKEY).unwrap();
    let encrypted = encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_handle: "alice".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string(),
        backend: &DeterministicBackend,
        ssh_pubkey: TEST_SSH_PUBKEY,
        ssh_fpr: ssh_fpr.clone(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        debug: false,
    })
    .expect("encrypt_private_key should succeed");

    let value = serde_json::to_value(&encrypted.protected.alg).unwrap();
    let object = value.as_object().unwrap();
    let fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();

    assert_eq!(
        fields,
        BTreeSet::from(["aead", "fpr", "hkdf_salt", "ikm_salt", "kdf"])
    );
    assert_eq!(object["kdf"], "sshsig-ed25519-hkdf-sha256");
    assert_eq!(object["fpr"], ssh_fpr);
    assert_eq!(object["aead"], algorithm::AEAD_XCHACHA20_POLY1305);
}

#[test]
fn test_decrypt_private_key_rejects_fingerprint_mismatch_before_kdf() {
    struct CountingBackend {
        calls: Cell<u32>,
    }

    impl SignatureBackend for CountingBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
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
        member_handle: "alice".to_string(),
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
fn test_decrypt_private_key_rejects_unsupported_aead_before_kdf() {
    struct CountingBackend {
        calls: Cell<u32>,
    }

    impl SignatureBackend for CountingBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
            self.calls.set(self.calls.get() + 1);
            Ok(Ed25519RawSignature::new([0xAB; 64]))
        }
    }

    let plaintext = build_test_plaintext();
    let backend = CountingBackend {
        calls: Cell::new(0),
    };
    let mut encrypted = encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_handle: "alice".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string(),
        backend: &backend,
        ssh_pubkey: TEST_SSH_PUBKEY,
        ssh_fpr: build_sha256_fingerprint(TEST_SSH_PUBKEY).unwrap(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        debug: false,
    })
    .unwrap();
    encrypted.protected.alg = match encrypted.protected.alg {
        PrivateKeyAlgorithm::SshSig {
            fpr,
            ikm_salt,
            hkdf_salt,
            ..
        } => PrivateKeyAlgorithm::SshSig {
            fpr,
            ikm_salt,
            hkdf_salt,
            aead: "aes-256-gcm".to_string(),
        },
        other => other,
    };

    let err = decrypt_private_key(&encrypted, &backend, TEST_SSH_PUBKEY, false).unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("aes-256-gcm") && err_msg.contains("xchacha20-poly1305"),
        "error should mention both actual and expected AEAD: {err_msg}"
    );
    assert_eq!(
        backend.calls.get(),
        2,
        "decrypt path must reject unsupported AEAD before signing"
    );
}

#[test]
fn test_decrypt_private_key_accepts_lowercase_fpr_prefix_roundtrip() {
    struct DeterministicBackend;
    impl SignatureBackend for DeterministicBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
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
        member_handle: "alice".to_string(),
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

#[test]
fn test_decrypt_private_key_retries_signature_only_after_failure() {
    struct CountingBackend {
        calls: Cell<u32>,
    }

    impl SignatureBackend for CountingBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
            self.calls.set(self.calls.get() + 1);
            Ok(Ed25519RawSignature::new([0xAB; 64]))
        }
    }

    let plaintext = build_test_plaintext();
    let backend = CountingBackend {
        calls: Cell::new(0),
    };
    let mut encrypted = encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_handle: "alice".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string(),
        backend: &backend,
        ssh_pubkey: TEST_SSH_PUBKEY,
        ssh_fpr: build_sha256_fingerprint(TEST_SSH_PUBKEY).unwrap(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        debug: false,
    })
    .unwrap();
    encrypted.encrypted.ct = tamper_base64url(&encrypted.encrypted.ct);

    let err = decrypt_private_key(&encrypted, &backend, TEST_SSH_PUBKEY, false).unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("E_PRIVATE_KEY_DECRYPT_FAILED"),
        "decrypt failure should use private key error code: {err_msg}"
    );
    assert_eq!(
        backend.calls.get(),
        4,
        "encrypt uses 2 signatures and decrypt failure retries once for diagnosis"
    );
}

#[test]
fn test_decrypt_private_key_sanitizes_plaintext_deserialize_error() {
    struct DeterministicBackend;

    impl SignatureBackend for DeterministicBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
            Ok(Ed25519RawSignature::new([0xAB; 64]))
        }
    }

    let backend = DeterministicBackend;
    let private_key = build_ssh_private_key_with_plaintext_json(b"{");

    let err = decrypt_private_key(&private_key, &backend, TEST_SSH_PUBKEY, false)
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
fn test_decrypt_private_key_reports_non_deterministic_after_failed_retry() {
    struct EncryptBackend;

    impl SignatureBackend for EncryptBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
            Ok(Ed25519RawSignature::new([0xAB; 64]))
        }
    }

    struct RetryDiagnosticBackend {
        calls: Cell<u32>,
    }

    impl SignatureBackend for RetryDiagnosticBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
            self.calls.set(self.calls.get() + 1);
            let fill = if self.calls.get() == 1 { 0xAB } else { 0xAC };
            Ok(Ed25519RawSignature::new([fill; 64]))
        }
    }

    let plaintext = build_test_plaintext();
    let mut encrypted = encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_handle: "alice".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string(),
        backend: &EncryptBackend,
        ssh_pubkey: TEST_SSH_PUBKEY,
        ssh_fpr: build_sha256_fingerprint(TEST_SSH_PUBKEY).unwrap(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        debug: false,
    })
    .unwrap();
    encrypted.encrypted.ct = tamper_base64url(&encrypted.encrypted.ct);

    let backend = RetryDiagnosticBackend {
        calls: Cell::new(0),
    };
    let err = decrypt_private_key(&encrypted, &backend, TEST_SSH_PUBKEY, false).unwrap_err();

    assert!(
        err.to_string().contains("W_SSH_NONDETERMINISTIC"),
        "retry diagnosis should report non-deterministic signatures: {err}"
    );
    assert_eq!(
        backend.calls.get(),
        2,
        "decrypt should retry once after failure"
    );
}

#[test]
fn test_decrypt_private_key_preserves_initial_ssh_error_without_retry() {
    struct EncryptBackend;

    impl SignatureBackend for EncryptBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
            Ok(Ed25519RawSignature::new([0xAB; 64]))
        }
    }

    struct FailingBackend {
        calls: Cell<u32>,
    }

    impl SignatureBackend for FailingBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> secretenv_core::Result<Ed25519RawSignature> {
            self.calls.set(self.calls.get() + 1);
            Err(secretenv_core::Error::build_ssh_error(
                "synthetic decrypt ssh failure".to_string(),
            ))
        }
    }

    let plaintext = build_test_plaintext();
    let encrypted = encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_handle: "alice".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string(),
        backend: &EncryptBackend,
        ssh_pubkey: TEST_SSH_PUBKEY,
        ssh_fpr: build_sha256_fingerprint(TEST_SSH_PUBKEY).unwrap(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        debug: false,
    })
    .unwrap();

    let backend = FailingBackend {
        calls: Cell::new(0),
    };
    let err = decrypt_private_key(&encrypted, &backend, TEST_SSH_PUBKEY, false).unwrap_err();

    assert!(
        err.to_string().contains("synthetic decrypt ssh failure"),
        "initial ssh signing failure should be preserved: {err}"
    );
    assert_eq!(
        backend.calls.get(),
        1,
        "initial ssh signing failure must not retry"
    );
}
