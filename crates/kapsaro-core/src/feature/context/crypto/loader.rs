// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore-backed crypto context loading.

use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use tracing::debug;

use super::{CryptoContext, LocalKeyAccess, LocalKeyIdentity, PrivateKeyLoadResult};
use crate::feature::context::expiry::{LocalKeyPairExpiry, VerifiedExpiresAt};
use crate::feature::key::material::validate_private_key_material;
use crate::feature::key::protection::encryption::decrypt_private_key;
use crate::feature::verify::private_key::verify_private_key_matches_public_key;
use crate::feature::verify::public_key::{
    verify_public_key_with_attestation_context, KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT,
};
use crate::format::codec::base64_secret::decode_base64url_nopad_secret_32;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::public_key_source::KeystorePublicKeySource;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext};
use crate::model::public_key::PublicKey;
use crate::model::verified::{DecryptionProof, VerifiedPrivateKey};
use crate::support::kid::format_kid_display;
use crate::{Error, Result};

pub(crate) fn build_signing_key(plaintext: &PrivateKeyPlaintext) -> Result<SigningKey> {
    let sig_key_bytes =
        decode_base64url_nopad_secret_32(&plaintext.keys.sig.d, "Ed25519 private key")?;
    Ok(SigningKey::from_bytes(sig_key_bytes.as_array()))
}

/// Validate private key plaintext and wrap it as SSH-decrypted key material.
pub(crate) fn build_verified_private_key_from_ssh(
    plaintext: PrivateKeyPlaintext,
    member_handle: &str,
    kid: &str,
    ssh_fpr: &str,
) -> Result<VerifiedPrivateKey> {
    validate_private_key_material(&plaintext)?;

    let proof = DecryptionProof {
        member_handle: member_handle.to_string(),
        kid: kid.to_string(),
        ssh_fpr: Some(ssh_fpr.to_string()),
    };
    Ok(VerifiedPrivateKey::new(plaintext, proof))
}

/// Validate private key plaintext and wrap it as password-decrypted key material.
pub fn build_verified_private_key_from_password(
    plaintext: PrivateKeyPlaintext,
    member_handle: &str,
    kid: &str,
) -> Result<VerifiedPrivateKey> {
    validate_private_key_material(&plaintext)?;

    let proof = DecryptionProof {
        member_handle: member_handle.to_string(),
        kid: kid.to_string(),
        ssh_fpr: None,
    };
    Ok(VerifiedPrivateKey::new(plaintext, proof))
}

pub(crate) fn build_local_key_access(
    keystore_access: KeystoreAccess,
    ssh_pubkey: String,
    ssh_backend: Box<dyn SignatureBackend>,
) -> LocalKeyAccess {
    LocalKeyAccess::new(keystore_access, ssh_pubkey, ssh_backend)
}

pub(crate) fn load_crypto_context_from_keystore(
    keystore_access: KeystoreAccess,
    member_handle: MemberHandle,
    explicit_kid: Option<&str>,
    ssh_backend: Box<dyn SignatureBackend>,
    ssh_pubkey: String,
    workspace_path: Option<PathBuf>,
) -> Result<CryptoContext> {
    let (kid, loaded) = resolve_and_load_verified_private_key(
        &keystore_access,
        &member_handle,
        explicit_kid,
        ssh_backend.as_ref(),
        &ssh_pubkey,
    )?;
    build_keystore_crypto_context(KeystoreCryptoContextInput {
        keystore_access,
        member_handle,
        kid,
        loaded,
        selected_kid_override: explicit_kid.is_some(),
        ssh_backend,
        ssh_pubkey,
        workspace_path,
    })
}

pub(crate) fn load_crypto_context_from_keystore_with_selected_kid(
    keystore_access: KeystoreAccess,
    member_handle: MemberHandle,
    selected_kid: Kid,
    selected_kid_override: bool,
    ssh_backend: Box<dyn SignatureBackend>,
    ssh_pubkey: String,
    workspace_path: Option<PathBuf>,
) -> Result<CryptoContext> {
    log_resolved_kid(&selected_kid);
    let loaded = load_verified_private_key_from_keystore(
        &keystore_access,
        &member_handle,
        &selected_kid,
        ssh_backend.as_ref(),
        &ssh_pubkey,
    )?;
    build_keystore_crypto_context(KeystoreCryptoContextInput {
        keystore_access,
        member_handle,
        kid: selected_kid,
        loaded,
        selected_kid_override,
        ssh_backend,
        ssh_pubkey,
        workspace_path,
    })
}

struct KeystoreCryptoContextInput {
    keystore_access: KeystoreAccess,
    member_handle: MemberHandle,
    kid: Kid,
    loaded: PrivateKeyLoadResult,
    selected_kid_override: bool,
    ssh_backend: Box<dyn SignatureBackend>,
    ssh_pubkey: String,
    workspace_path: Option<PathBuf>,
}

fn build_keystore_crypto_context(input: KeystoreCryptoContextInput) -> Result<CryptoContext> {
    let signing_key = build_signing_key(input.loaded.private_key.document())?;
    let selected_kid_override = input.selected_kid_override.then(|| input.kid.clone());
    let context = CryptoContext::new(
        input.member_handle,
        input.kid,
        Box::new(KeystorePublicKeySource::new(input.keystore_access.clone())),
        input.workspace_path,
        input.loaded.private_key,
        signing_key,
        input.loaded.key_expiry,
    );
    Ok(context.with_local_key_access(
        selected_kid_override,
        Some(build_local_key_access(
            input.keystore_access,
            input.ssh_pubkey,
            input.ssh_backend,
        )),
    ))
}

/// Resolve which key the caller asked for and load it in one keystore read.
///
/// The keystore settles both under a single lock on the member directory, so
/// an activation landing mid-command cannot leave the resolved key id naming a
/// different key than the documents that came back with it.
fn resolve_and_load_verified_private_key(
    keystore_access: &KeystoreAccess,
    member_handle: &MemberHandle,
    explicit_kid: Option<&str>,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
) -> Result<(Kid, PrivateKeyLoadResult)> {
    let (kid, encrypted_private_key, public_key) =
        keystore_access.resolve_key_pair(member_handle, explicit_kid)?;
    log_resolved_kid(&kid);
    let loaded =
        verify_and_decrypt_key_pair(encrypted_private_key, public_key, backend, ssh_pubkey)?;
    Ok((kid, loaded))
}

fn log_resolved_kid(kid: &Kid) {
    if tracing::enabled!(tracing::Level::DEBUG) {
        let kid_display =
            format_kid_display(kid.as_str()).unwrap_or_else(|_| kid.as_str().to_string());
        debug!("[CRYPTO] load_crypto_context: resolved kid={}", kid_display);
    }
}

pub(crate) fn load_verified_private_key_from_keystore(
    keystore_access: &KeystoreAccess,
    member_handle: &MemberHandle,
    kid: &Kid,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
) -> Result<PrivateKeyLoadResult> {
    let (encrypted_private_key, public_key) = keystore_access.load_key_pair(member_handle, kid)?;
    verify_and_decrypt_key_pair(encrypted_private_key, public_key, backend, ssh_pubkey)
}

/// Verify one stored key pair against itself and unlock the private half.
fn verify_and_decrypt_key_pair(
    encrypted_private_key: PrivateKey,
    public_key: PublicKey,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
) -> Result<PrivateKeyLoadResult> {
    let verified_public_key = verify_public_key_with_attestation_context(
        &public_key,
        KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT,
    )?;
    verify_private_key_matches_public_key(&encrypted_private_key, verified_public_key.document())?;

    let plaintext = decrypt_private_key(&encrypted_private_key, backend, ssh_pubkey)?;
    let private_key = build_verified_private_key_from_ssh(
        plaintext,
        &encrypted_private_key.protected.subject_handle,
        &encrypted_private_key.protected.kid,
        extract_ssh_fingerprint(&encrypted_private_key)?,
    )?;

    Ok(PrivateKeyLoadResult {
        private_key,
        key_identity: LocalKeyIdentity::from_public_key(verified_public_key.document())?,
        key_expiry: LocalKeyPairExpiry::from_private_and_public_key(
            VerifiedExpiresAt::from_verified_private_key_metadata(
                encrypted_private_key.protected.expires_at.clone(),
            ),
            VerifiedExpiresAt::from_verified_public_key_metadata(
                verified_public_key.document().protected.expires_at.clone(),
            ),
        ),
    })
}

fn extract_ssh_fingerprint(private_key: &PrivateKey) -> Result<&str> {
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, .. } => Ok(fpr.as_str()),
        _ => Err(Error::build_crypto_error(
            "Expected SshSig algorithm for SSH-based decryption".to_string(),
        )),
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/feature_context_crypto_loader_test.rs"]
mod feature_context_crypto_loader_test;
