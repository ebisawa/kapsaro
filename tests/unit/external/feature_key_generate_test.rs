// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/key/generate module.
//!
//! Tests for untested functions:
//! - build_private_key_plaintext (tested indirectly via keygen_test)
//! - save_and_activate (tested via public save_key_pair_atomic + set_active_kid)
//! - ensure_keystore_dir (tested via KeystoreResolver::ensure_keystore_root)
//! - build_public_key with github_account

use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{keygen_test, setup_test_keystore_from_fixtures};
use ed25519_dalek::{SigningKey, VerifyingKey};
use secretenv::crypto::kem::{derive_public_key_from_secret, X25519SecretKey};
use secretenv::feature::key::generate::KeyGenerationOptions;
use secretenv::feature::key::material::{build_identity_keys, generate_keypairs, KeypairMaterial};
use secretenv::feature::key::public_key_document::{build_public_key, PublicKeyDocumentParams};
use secretenv::feature::key::ssh_binding::SshBindingContext;
use secretenv::format::kid::derive_public_key_kid;
use secretenv::io::keystore::active::load_active_kid;
use secretenv::io::keystore::resolver::KeystoreResolver;
use secretenv::io::keystore::signer::load_signer_public_key;
use secretenv::io::keystore::storage::{list_kids, save_key_pair_atomic};
use secretenv::io::ssh::backend::signature_backend::SignatureBackend;
use secretenv::io::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN;
use secretenv::io::ssh::protocol::types::Ed25519RawSignature;
use secretenv::model::public_key::{Attestation, GithubAccount, Identity};
use secretenv::model::ssh::SshDeterminismStatus;
use secretenv::model::wire::jwk::{CRV_ED25519, CRV_X25519};
use secretenv::support::codec::base64_public::decode_base64url_nopad;
use tempfile::TempDir;
use zeroize::ZeroizeOnDrop;

// ============================================================================
// build_private_key_plaintext tests (indirect via keygen_test)
// ============================================================================

#[test]
fn test_build_private_key_plaintext_fields() {
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) =
        crate::test_utils::generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (plaintext, _public_key) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    // Verify KEM key fields
    assert_eq!(plaintext.keys.kem.kty, "OKP");
    assert_eq!(plaintext.keys.kem.crv, CRV_X25519);
    assert!(!plaintext.keys.kem.x.is_empty(), "kem.x must be non-empty");
    assert!(!plaintext.keys.kem.d.is_empty(), "kem.d must be non-empty");

    // Verify signing key fields
    assert_eq!(plaintext.keys.sig.kty, "OKP");
    assert_eq!(plaintext.keys.sig.crv, CRV_ED25519);
    assert!(!plaintext.keys.sig.x.is_empty(), "sig.x must be non-empty");
    assert!(!plaintext.keys.sig.d.is_empty(), "sig.d must be non-empty");
}

#[test]
fn test_build_private_key_plaintext_base64url_encoded() {
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) =
        crate::test_utils::generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (plaintext, _public_key) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    // All x and d fields must be valid base64url
    let kem_x = decode_base64url_nopad(&plaintext.keys.kem.x, "kem.x");
    assert!(kem_x.is_ok(), "kem.x must be valid base64url");
    assert_eq!(kem_x.unwrap().len(), 32, "X25519 public key is 32 bytes");

    let kem_d = decode_base64url_nopad(&plaintext.keys.kem.d, "kem.d");
    assert!(kem_d.is_ok(), "kem.d must be valid base64url");
    assert_eq!(kem_d.unwrap().len(), 32, "X25519 secret key is 32 bytes");

    let sig_x = decode_base64url_nopad(&plaintext.keys.sig.x, "sig.x");
    assert!(sig_x.is_ok(), "sig.x must be valid base64url");
    assert_eq!(sig_x.unwrap().len(), 32, "Ed25519 public key is 32 bytes");

    let sig_d = decode_base64url_nopad(&plaintext.keys.sig.d, "sig.d");
    assert!(sig_d.is_ok(), "sig.d must be valid base64url");
    assert_eq!(sig_d.unwrap().len(), 32, "Ed25519 secret key is 32 bytes");
}

#[test]
fn test_build_private_key_plaintext_key_consistency() {
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) =
        crate::test_utils::generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (plaintext, public_key) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    // The public key's x field in kem should match the private key's x field in kem
    assert_eq!(
        plaintext.keys.kem.x, public_key.protected.identity.keys.kem.x,
        "KEM public key in private and public key documents must match"
    );

    // The public key's x field in sig should match the private key's x field in sig
    assert_eq!(
        plaintext.keys.sig.x, public_key.protected.identity.keys.sig.x,
        "Signing public key in private and public key documents must match"
    );
}

// ============================================================================
// build_public_key with/without github_account
// ============================================================================

fn build_protected_without_kid_value(
    public_key: &secretenv::model::public_key::PublicKey,
) -> serde_json::Value {
    let mut value = serde_json::to_value(&public_key.protected).unwrap();
    value
        .as_object_mut()
        .expect("public key protected must be a JSON object")
        .remove("kid");
    value
}

fn generate_test_identity() -> (Identity, ed25519_dalek::SigningKey) {
    let keypairs = generate_keypairs().unwrap();
    let identity_keys = build_identity_keys(&keypairs.kem_pk, &keypairs.sig_pk).unwrap();
    let identity = Identity {
        keys: identity_keys,
        attestation: Attestation {
            method: ATTESTATION_METHOD_SSH_SIGN.to_string(),
            pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE".to_string(),
            sig: "dummy".to_string(),
        },
    };
    (identity, keypairs.sig_sk.clone())
}

#[test]
fn test_build_public_key_with_github_account() {
    let (identity, sig_sk) = generate_test_identity();

    let github_account = GithubAccount {
        id: 12345,
        login: "testuser".to_string(),
    };

    let public_key = build_public_key(&PublicKeyDocumentParams {
        member_handle: ALICE_MEMBER_HANDLE,
        identity,
        created_at: "2024-01-01T00:00:00Z",
        expires_at: "2025-01-01T00:00:00Z",
        sig_sk: &sig_sk,
        debug: false,
        github_account: Some(github_account),
    })
    .unwrap();

    let binding = public_key.protected.binding_claims.as_ref();
    assert!(binding.is_some(), "binding_claims must be present");

    let github = binding.unwrap().github_account.as_ref();
    assert!(github.is_some(), "github_account must be present");
    assert_eq!(github.unwrap().id, 12345);
    assert_eq!(github.unwrap().login, "testuser");
    assert_eq!(
        public_key.protected.kid,
        derive_public_key_kid(&build_protected_without_kid_value(&public_key)).unwrap()
    );
}

#[test]
fn test_build_public_key_without_github_account() {
    let (identity, sig_sk) = generate_test_identity();

    let public_key = build_public_key(&PublicKeyDocumentParams {
        member_handle: ALICE_MEMBER_HANDLE,
        identity,
        created_at: "2024-01-01T00:00:00Z",
        expires_at: "2025-01-01T00:00:00Z",
        sig_sk: &sig_sk,
        debug: false,
        github_account: None,
    })
    .unwrap();

    assert!(
        public_key.protected.binding_claims.is_none(),
        "binding_claims must be None when no github_account"
    );
    assert_eq!(
        public_key.protected.kid,
        derive_public_key_kid(&build_protected_without_kid_value(&public_key)).unwrap()
    );
}

#[test]
fn test_build_public_key_self_signature_valid_base64url() {
    let (identity, sig_sk) = generate_test_identity();

    let public_key = build_public_key(&PublicKeyDocumentParams {
        member_handle: ALICE_MEMBER_HANDLE,
        identity,
        created_at: "2024-01-01T00:00:00Z",
        expires_at: "2025-01-01T00:00:00Z",
        sig_sk: &sig_sk,
        debug: false,
        github_account: None,
    })
    .unwrap();

    assert!(
        !public_key.signature.is_empty(),
        "signature must be non-empty"
    );

    // Signature should be valid base64url
    let decoded = decode_base64url_nopad(&public_key.signature, "signature");
    assert!(decoded.is_ok(), "signature must be valid base64url");

    // Ed25519 signature is 64 bytes
    assert_eq!(decoded.unwrap().len(), 64, "Ed25519 signature is 64 bytes");
}

#[test]
fn test_build_public_key_changes_kid_when_github_account_changes() {
    let (identity_with_claim, sig_sk_with_claim) = generate_test_identity();
    let with_claim = build_public_key(&PublicKeyDocumentParams {
        member_handle: ALICE_MEMBER_HANDLE,
        identity: identity_with_claim,
        created_at: "2024-01-01T00:00:00Z",
        expires_at: "2025-01-01T00:00:00Z",
        sig_sk: &sig_sk_with_claim,
        debug: false,
        github_account: Some(GithubAccount {
            id: 12345,
            login: "testuser".to_string(),
        }),
    })
    .unwrap();
    let (identity_without_claim, sig_sk_without_claim) = generate_test_identity();
    let without_claim = build_public_key(&PublicKeyDocumentParams {
        member_handle: ALICE_MEMBER_HANDLE,
        identity: identity_without_claim,
        created_at: "2024-01-01T00:00:00Z",
        expires_at: "2025-01-01T00:00:00Z",
        sig_sk: &sig_sk_without_claim,
        debug: false,
        github_account: None,
    })
    .unwrap();

    assert_ne!(with_claim.protected.kid, without_claim.protected.kid);
}

#[test]
fn test_derive_key_from_ssh_preserves_ssh_backend_errors() {
    struct FailingBackend;

    impl SignatureBackend for FailingBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _ssh_pubkey: &str,
            _challenge_bytes: &[u8],
        ) -> secretenv::Result<Ed25519RawSignature> {
            Err(secretenv::Error::Ssh {
                message: "ssh-keygen -Y sign failed: synthetic backend failure".to_string(),
                source: None,
            })
        }
    }

    let result = secretenv::feature::key::protection::key_derivation::derive_key_from_ssh(
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &secretenv::crypto::types::primitives::HkdfSalt::new([7u8; 32]),
        &FailingBackend,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@example.com",
        false,
    );

    let error = match result {
        Ok(_) => panic!("ssh backend errors must propagate"),
        Err(error) => error,
    };
    let error_message = error.to_string();
    assert!(
        error_message.contains("synthetic backend failure"),
        "original SSH error should be preserved: {}",
        error_message
    );
    assert!(
        !error_message.contains("W_SSH_NONDETERMINISTIC"),
        "backend failures must not be reclassified as non-deterministic: {}",
        error_message
    );
}

#[test]
fn test_derive_key_from_ssh_maps_non_deterministic_error() {
    use std::cell::Cell;

    struct NonDeterministicBackend {
        counter: Cell<u8>,
    }

    impl SignatureBackend for NonDeterministicBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _ssh_pubkey: &str,
            _challenge_bytes: &[u8],
        ) -> secretenv::Result<Ed25519RawSignature> {
            let mut bytes = [0u8; 64];
            bytes[0] = self.counter.get();
            self.counter.set(bytes[0] + 1);
            Ok(Ed25519RawSignature::new(bytes))
        }
    }

    let result = secretenv::feature::key::protection::key_derivation::derive_key_from_ssh(
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        &secretenv::crypto::types::primitives::HkdfSalt::new([9u8; 32]),
        &NonDeterministicBackend {
            counter: Cell::new(0),
        },
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@example.com",
        false,
    );

    let error = match result {
        Ok(_) => panic!("non-deterministic signatures must fail"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("W_SSH_NONDETERMINISTIC"),
        "non-deterministic failures should map to warning code: {}",
        error
    );
}

// ============================================================================
// save_and_activate tests (via public functions)
// ============================================================================

#[test]
fn test_save_and_activate_activates() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");

    // Generate a new key pair
    let (plaintext, public_key) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let new_kid = &public_key.protected.kid;
    let private_key = crate::test_utils::build_test_private_key(
        &plaintext,
        ALICE_MEMBER_HANDLE,
        new_kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();

    // Simulate save_and_activate with no_activate=false
    save_key_pair_atomic(
        &keystore_root,
        ALICE_MEMBER_HANDLE,
        new_kid,
        &private_key,
        &public_key,
    )
    .unwrap();
    // no_activate=false means we DO activate
    secretenv::io::keystore::active::set_active_kid(ALICE_MEMBER_HANDLE, new_kid, &keystore_root)
        .unwrap();

    let active = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root).unwrap();
    assert_eq!(
        active.as_deref(),
        Some(new_kid.as_str()),
        "Key should be active after save_and_activate with no_activate=false"
    );
}

#[test]
fn test_save_and_activate_no_activate() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_root = temp_dir.path().join("keys");
    std::fs::create_dir_all(&keystore_root).unwrap();

    let (ssh_priv, _ssh_pub_path, ssh_pub_content) =
        crate::test_utils::generate_temp_ssh_keypair_in_dir(&temp_dir);

    // Generate a new key pair
    let (plaintext, public_key) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let new_kid = &public_key.protected.kid;
    let private_key = crate::test_utils::build_test_private_key(
        &plaintext,
        ALICE_MEMBER_HANDLE,
        new_kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();

    // Simulate save_and_activate with no_activate=true
    // Only save, do NOT set active
    save_key_pair_atomic(
        &keystore_root,
        ALICE_MEMBER_HANDLE,
        new_kid,
        &private_key,
        &public_key,
    )
    .unwrap();

    // Key files should exist
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    assert!(kids.contains(&new_kid.to_string()), "Key should be saved");

    // But no active kid should be set
    let active = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root).unwrap();
    assert!(
        active.is_none(),
        "No key should be active after save_and_activate with no_activate=true"
    );
}

// ============================================================================
// ensure_keystore_dir tests (via KeystoreResolver::ensure_keystore_root)
// ============================================================================

#[test]
fn test_ensure_keystore_dir_creates_directory() {
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path().to_path_buf();
    let expected_keystore = home.join("keys");

    // Directory should not exist yet
    assert!(!expected_keystore.exists());

    let result = KeystoreResolver::ensure_keystore_root(Some(&home)).unwrap();

    assert_eq!(result, expected_keystore);
    assert!(
        expected_keystore.exists(),
        "Keystore directory should be created"
    );
    assert!(
        expected_keystore.is_dir(),
        "Keystore path should be a directory"
    );
}

#[test]
fn test_ensure_keystore_dir_idempotent() {
    let temp_dir = TempDir::new().unwrap();
    let home = temp_dir.path().to_path_buf();

    // Call twice - second call should succeed without error
    let result1 = KeystoreResolver::ensure_keystore_root(Some(&home)).unwrap();
    let result2 = KeystoreResolver::ensure_keystore_root(Some(&home)).unwrap();

    assert_eq!(result1, result2, "Both calls should return the same path");
}

// ============================================================================
// Tests merged from services_keys_test.rs
// ============================================================================

#[test]
fn test_generate_keypairs() {
    let keypairs = generate_keypairs().unwrap();
    assert_eq!(keypairs.kem_pk.as_bytes().len(), 32);
    assert_eq!(keypairs.sig_pk.as_bytes().len(), 32);
}

#[test]
fn test_generated_key_material_zeroize_on_drop_contract() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<X25519SecretKey>();
    assert_zeroize_on_drop::<KeypairMaterial>();
}

#[test]
fn test_build_identity_keys() {
    let kem_sk = X25519SecretKey::from_bytes([1u8; 32]);
    let kem_pk = derive_public_key_from_secret(&kem_sk).unwrap();
    let sig_sk = SigningKey::from_bytes(&[2u8; 32]);
    let sig_pk: VerifyingKey = sig_sk.verifying_key();

    let identity_keys = build_identity_keys(&kem_pk, &sig_pk).unwrap();

    assert_eq!(identity_keys.kem.crv, CRV_X25519);
    assert_eq!(identity_keys.sig.crv, CRV_ED25519);
}

#[test]
fn test_build_public_key() {
    let (_temp_dir, keypairs) = {
        let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
        let keypairs = generate_keypairs().unwrap();
        (temp_dir, keypairs)
    };
    let identity_keys = build_identity_keys(&keypairs.kem_pk, &keypairs.sig_pk).unwrap();

    let identity = Identity {
        keys: identity_keys,
        attestation: Attestation {
            method: ATTESTATION_METHOD_SSH_SIGN.to_string(),
            pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE".to_string(),
            sig: "dummy".to_string(),
        },
    };

    let public_key = build_public_key(&PublicKeyDocumentParams {
        member_handle: ALICE_MEMBER_HANDLE,
        identity,
        created_at: "2024-01-01T00:00:00Z",
        expires_at: "2025-01-01T00:00:00Z",
        sig_sk: &keypairs.sig_sk,
        debug: false,
        github_account: None,
    })
    .unwrap();

    assert_eq!(public_key.protected.subject_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(
        public_key.protected.kid,
        derive_public_key_kid(&build_protected_without_kid_value(&public_key)).unwrap()
    );
    assert!(!public_key.signature.is_empty());
}

#[test]
fn test_load_signer_public_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let pub_key_source =
        secretenv::io::keystore::public_key_source::KeystorePublicKeySource::new(keystore_root);

    let result = load_signer_public_key(&pub_key_source, ALICE_MEMBER_HANDLE).unwrap();

    assert_eq!(result.protected.subject_handle, ALICE_MEMBER_HANDLE);
}

#[test]
fn test_generate_key_rejects_skipped_determinism() {
    let temp_dir = TempDir::new().unwrap();
    let ssh_temp = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) =
        crate::test_utils::generate_temp_ssh_keypair_in_dir(&ssh_temp);

    let ssh_keygen =
        secretenv::io::ssh::external::keygen::DefaultSshKeygen::new("ssh-keygen".to_string());
    let descriptor =
        secretenv::io::ssh::protocol::key_descriptor::SshKeyDescriptor::from_path(ssh_priv);
    let backend: Box<dyn SignatureBackend> = Box::new(
        secretenv::io::ssh::backend::ssh_keygen::SshKeygenBackend::new(
            Box::new(ssh_keygen),
            descriptor,
        ),
    );
    let fingerprint =
        secretenv::io::ssh::protocol::build_sha256_fingerprint(ssh_pub_content.trim()).unwrap();

    let ssh_binding = SshBindingContext {
        public_key: ssh_pub_content.trim().to_string(),
        fingerprint,
        backend,
        determinism: SshDeterminismStatus::Skipped,
    };

    let now = time::OffsetDateTime::now_utc();
    let created_at = secretenv::support::time::format_timestamp_rfc3339(now).unwrap();
    let expires_at =
        secretenv::support::time::format_timestamp_rfc3339(now + time::Duration::days(365))
            .unwrap();

    let result = secretenv::feature::key::generate::generate_key(KeyGenerationOptions {
        member_handle: ALICE_MEMBER_HANDLE.to_string(),
        home: Some(temp_dir.path().to_path_buf()),
        created_at,
        expires_at,
        no_activate: false,
        debug: false,
        github_account: None,
        verbose: false,
        ssh_binding,
    });

    let err_msg = match result {
        Ok(_) => panic!("generate_key must reject Skipped determinism"),
        Err(e) => e.to_string(),
    };
    assert!(
        err_msg.contains("determinism check was not performed"),
        "Error should mention missing determinism check, got: {}",
        err_msg
    );
}
