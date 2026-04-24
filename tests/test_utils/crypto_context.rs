// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared CryptoContext builder for tests
//!
//! Uses Ed25519DirectBackend to avoid spawning ssh-keygen subprocesses.

use super::ed25519_backend::Ed25519DirectBackend;
use ed25519_dalek::SigningKey;
use secretenv::feature::context::crypto::{build_local_key_access, CryptoContext};
use secretenv::feature::key::material::{validate_ed25519_consistency, validate_okp_key};
use secretenv::feature::key::protection::encryption::decrypt_private_key;
use secretenv::feature::verify::private_key::verify_private_key_matches_public_key;
use secretenv::feature::verify::public_key::verify_public_key_with_attestation;
use secretenv::io::keystore::helpers::resolve_kid;
use secretenv::io::keystore::public_key_source::KeystorePublicKeySource;
use secretenv::io::keystore::storage::{load_private_key, load_public_key};
use secretenv::io::ssh::backend::SignatureBackend;
use secretenv::model::identity::{Kid, MemberId};
use secretenv::model::private_key::{PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext};
use secretenv::model::verified::{DecryptionProof, VerifiedPrivateKey};
use secretenv::support::codec::base64_public::decode_base64url_nopad_array;
use std::fs;
use tempfile::TempDir;

/// Build CryptoContext for a member in a test keystore
///
/// Uses Ed25519DirectBackend instead of SshKeygenBackend to avoid
/// spawning ssh-keygen subprocesses.
pub fn setup_member_key_context(
    temp_dir: &TempDir,
    member_id: &str,
    explicit_kid: Option<&str>,
) -> CryptoContext {
    let keystore_root = temp_dir.path().join("keys");
    let ssh_pub = load_test_ssh_public_key(temp_dir);
    let backend = build_test_signature_backend(temp_dir);
    let (resolved_kid, private_key, public_key) =
        load_test_key_material(&keystore_root, member_id, explicit_kid);
    let verified_private_key =
        load_verified_private_key(&private_key, &public_key, backend.as_ref(), &ssh_pub);
    let signing_key = build_test_signing_key(verified_private_key.document()).unwrap();

    CryptoContext::new(
        MemberId::try_from(member_id.to_string()).unwrap(),
        Kid::try_from(resolved_kid.clone()).unwrap(),
        Box::new(KeystorePublicKeySource::new(keystore_root.clone())),
        Some(temp_dir.path().join("workspace")),
        verified_private_key,
        signing_key,
        private_key.protected.expires_at.clone(),
    )
    .with_local_key_access(
        explicit_kid.map(|_| resolved_kid),
        Some(build_local_key_access(keystore_root, ssh_pub, backend)),
    )
}

fn load_test_ssh_public_key(temp_dir: &TempDir) -> String {
    fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string()
}

fn build_test_signature_backend(temp_dir: &TempDir) -> Box<dyn SignatureBackend> {
    let ssh_priv = temp_dir.path().join(".ssh").join("test_ed25519");
    Box::new(Ed25519DirectBackend::new(&ssh_priv).unwrap())
}

fn load_test_key_material(
    keystore_root: &std::path::Path,
    member_id: &str,
    kid: Option<&str>,
) -> (String, PrivateKey, secretenv::model::public_key::PublicKey) {
    let kid = resolve_kid(keystore_root, member_id, kid).unwrap();
    let private_key = load_private_key(keystore_root, member_id, &kid).unwrap();
    let public_key = load_public_key(keystore_root, member_id, &kid).unwrap();
    (kid, private_key, public_key)
}

fn load_verified_private_key(
    private_key: &PrivateKey,
    public_key: &secretenv::model::public_key::PublicKey,
    backend: &dyn SignatureBackend,
    ssh_pub: &str,
) -> VerifiedPrivateKey {
    let verified_public_key = verify_public_key_with_attestation(public_key, false).unwrap();
    verify_private_key_matches_public_key(private_key, verified_public_key.document()).unwrap();
    let plaintext = decrypt_private_key(private_key, backend, ssh_pub, false).unwrap();
    build_verified_private_key(private_key, plaintext)
}

fn build_verified_private_key(
    private_key: &PrivateKey,
    plaintext: PrivateKeyPlaintext,
) -> VerifiedPrivateKey {
    validate_test_private_key_material(&plaintext).unwrap();
    VerifiedPrivateKey::new(
        plaintext,
        DecryptionProof::new(
            private_key.protected.member_id.clone(),
            private_key.protected.kid.clone(),
            Some(resolve_ssh_fingerprint(private_key).to_string()),
        ),
    )
}

fn validate_test_private_key_material(plaintext: &PrivateKeyPlaintext) -> secretenv::Result<()> {
    let kem = &plaintext.keys.kem;
    validate_okp_key(&kem.kty, &kem.crv, "X25519", &kem.d, &kem.x, "KEM")?;

    let sig = &plaintext.keys.sig;
    let (sig_d_bytes, sig_x_bytes) =
        validate_okp_key(&sig.kty, &sig.crv, "Ed25519", &sig.d, &sig.x, "Sig")?;
    validate_ed25519_consistency(&sig_d_bytes, &sig_x_bytes)?;
    Ok(())
}

fn build_test_signing_key(plaintext: &PrivateKeyPlaintext) -> secretenv::Result<SigningKey> {
    let bytes = decode_base64url_nopad_array(&plaintext.keys.sig.d, "Ed25519 private key")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn resolve_ssh_fingerprint(private_key: &PrivateKey) -> &str {
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, .. } => fpr.as_str(),
        _ => panic!("expected SSH-protected private key"),
    }
}
