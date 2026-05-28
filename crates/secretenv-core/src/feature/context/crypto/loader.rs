// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore-backed crypto context loading.

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
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
use crate::io::keystore::helpers::resolve_kid;
use crate::io::keystore::public_key_source::KeystorePublicKeySource;
use crate::io::keystore::storage::{load_private_key, load_public_key};
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext};
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

pub fn build_local_key_access(
    keystore_root: PathBuf,
    ssh_pubkey: String,
    ssh_backend: Box<dyn SignatureBackend>,
) -> LocalKeyAccess {
    LocalKeyAccess::new(keystore_root, ssh_pubkey, ssh_backend)
}

pub fn load_crypto_context_from_keystore(
    keystore_root: PathBuf,
    member_handle: &str,
    explicit_kid: Option<&str>,
    ssh_backend: Box<dyn SignatureBackend>,
    ssh_pubkey: String,
    workspace_path: Option<PathBuf>,
    debug_enabled: bool,
) -> Result<CryptoContext> {
    let kid = resolve_keystore_kid(&keystore_root, member_handle, explicit_kid, debug_enabled)?;
    let loaded = load_verified_private_key_from_keystore(
        &keystore_root,
        member_handle,
        &kid,
        ssh_backend.as_ref(),
        &ssh_pubkey,
        debug_enabled,
    )?;
    let selected_kid_override = explicit_kid
        .map(|_| Kid::try_from(loaded.private_key.proof().kid().to_string()))
        .transpose()?;
    let signing_key = build_signing_key(loaded.private_key.document())?;
    let context = CryptoContext::new(
        MemberHandle::try_from(member_handle)?,
        Kid::try_from(kid)?,
        Box::new(KeystorePublicKeySource::new(keystore_root.clone())),
        workspace_path,
        loaded.private_key,
        signing_key,
        loaded.key_expiry,
    );
    Ok(context.with_local_key_access(
        selected_kid_override,
        Some(build_local_key_access(
            keystore_root,
            ssh_pubkey,
            ssh_backend,
        )),
    ))
}

fn resolve_keystore_kid(
    keystore_root: &Path,
    member_handle: &str,
    explicit_kid: Option<&str>,
    debug_enabled: bool,
) -> Result<String> {
    let kid = resolve_kid(keystore_root, member_handle, explicit_kid)?;
    if debug_enabled {
        let kid_display = format_kid_display(&kid).unwrap_or_else(|_| kid.clone());
        debug!("[CRYPTO] load_crypto_context: resolved kid={}", kid_display);
    }
    Ok(kid)
}

pub(crate) fn load_verified_private_key_from_keystore(
    keystore_root: &Path,
    member_handle: &str,
    kid: &str,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    debug_enabled: bool,
) -> Result<PrivateKeyLoadResult> {
    let encrypted_private_key = load_private_key(keystore_root, member_handle, kid)?;
    let public_key = load_public_key(keystore_root, member_handle, kid)?;
    let verified_public_key = verify_public_key_with_attestation_context(
        &public_key,
        debug_enabled,
        KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT,
    )?;
    verify_private_key_matches_public_key(&encrypted_private_key, verified_public_key.document())?;

    let plaintext =
        decrypt_private_key(&encrypted_private_key, backend, ssh_pubkey, debug_enabled)?;
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
