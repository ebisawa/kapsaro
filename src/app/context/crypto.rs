// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use tracing::debug;

use crate::feature::context::crypto::{
    build_signing_key, validate_and_wrap_private_key_ssh, CryptoContext,
};
use crate::feature::key::protection::encryption::decrypt_private_key;
use crate::feature::verify::private_key::verify_private_key_matches_public_key;
use crate::feature::verify::public_key::verify_public_key_with_attestation;
use crate::io::config::paths::get_base_dir;
use crate::io::keystore::helpers::resolve_kid;
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::io::keystore::public_key_source::{
    KeystorePublicKeySource, PublicKeySource, WorkspacePublicKeySource,
};
use crate::io::keystore::storage::{load_private_key, load_public_key};
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identity::{Kid, MemberId};
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm};
use crate::model::verified::VerifiedPrivateKey;
use crate::support::kid::build_kid_display;
use crate::{Error, Result};

struct DecryptedSshKeyData {
    private_key: VerifiedPrivateKey,
    expires_at: String,
}

pub fn load_crypto_context(
    member_id: &str,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    explicit_kid: Option<&str>,
    keystore_root: Option<&PathBuf>,
    workspace_path: Option<PathBuf>,
    debug_enabled: bool,
) -> Result<CryptoContext> {
    log_crypto_context_load(member_id, explicit_kid, debug_enabled);
    let keystore_root = resolve_keystore_root(keystore_root)?;
    let kid = resolve_keystore_kid(&keystore_root, member_id, explicit_kid, debug_enabled)?;
    let encrypted_private_key =
        load_and_verify_keystore_private_key(&keystore_root, member_id, &kid, debug_enabled)?;
    let decrypted_key =
        decrypt_and_wrap_ssh_key(&encrypted_private_key, backend, ssh_pubkey, debug_enabled)?;
    build_keystore_crypto_context(member_id, kid, keystore_root, workspace_path, decrypted_key)
}

pub fn load_crypto_context_from_env(
    workspace_path: PathBuf,
    debug_enabled: bool,
) -> Result<CryptoContext> {
    let result = crate::feature::context::env_key::load_private_key_from_env(debug_enabled)?;
    let kid = Kid::try_from(result.verified_key.proof().kid.clone())?;
    let signing_key = build_signing_key(result.verified_key.document())?;

    Ok(CryptoContext {
        member_id: result.member_id,
        kid,
        pub_key_source: Box::new(WorkspacePublicKeySource::new(workspace_path.clone())),
        workspace_path: Some(workspace_path),
        private_key: result.verified_key,
        signing_key,
        expires_at: result.expires_at,
    })
}

fn log_crypto_context_load(member_id: &str, explicit_kid: Option<&str>, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[CRYPTO] load_crypto_context: member_id={}, explicit_kid={}",
            member_id,
            explicit_kid.unwrap_or("(none)")
        );
    }
}

fn resolve_keystore_root(keystore_root: Option<&PathBuf>) -> Result<PathBuf> {
    match keystore_root {
        Some(path) => Ok(path.clone()),
        None => {
            let base_dir = get_base_dir()?;
            Ok(get_keystore_root_from_base(&base_dir))
        }
    }
}

fn resolve_keystore_kid(
    keystore_root: &Path,
    member_id: &str,
    explicit_kid: Option<&str>,
    debug_enabled: bool,
) -> Result<String> {
    let kid = resolve_kid(keystore_root, member_id, explicit_kid)?;
    if debug_enabled {
        let kid_display = build_kid_display(&kid).unwrap_or_else(|_| kid.clone());
        debug!("[CRYPTO] load_crypto_context: resolved kid={}", kid_display);
    }
    Ok(kid)
}

fn load_and_verify_keystore_private_key(
    keystore_root: &Path,
    member_id: &str,
    kid: &str,
    debug_enabled: bool,
) -> Result<PrivateKey> {
    let encrypted_private_key = load_private_key(keystore_root, member_id, kid)?;

    // Keystore invariant: private/public pair under the same `<kid>/` directory should match.
    // (env key mode intentionally skips this, but keystore mode can verify it.)
    let public_key = load_public_key(keystore_root, member_id, kid)?;
    let verified_public_key = verify_public_key_with_attestation(&public_key, debug_enabled)?;
    verify_private_key_matches_public_key(&encrypted_private_key, verified_public_key.document())?;
    Ok(encrypted_private_key)
}

fn decrypt_and_wrap_ssh_key(
    encrypted_private_key: &PrivateKey,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    debug_enabled: bool,
) -> Result<DecryptedSshKeyData> {
    let plaintext = decrypt_private_key(encrypted_private_key, backend, ssh_pubkey, debug_enabled)?;
    let private_key = validate_and_wrap_private_key_ssh(
        plaintext,
        &encrypted_private_key.protected.member_id,
        &encrypted_private_key.protected.kid,
        extract_ssh_fingerprint(encrypted_private_key)?,
    )?;

    Ok(DecryptedSshKeyData {
        private_key,
        expires_at: encrypted_private_key.protected.expires_at.clone(),
    })
}

fn extract_ssh_fingerprint(private_key: &PrivateKey) -> Result<&str> {
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, .. } => Ok(fpr.as_str()),
        _ => Err(Error::Crypto {
            message: "Expected SshSig algorithm for SSH-based decryption".to_string(),
            source: None,
        }),
    }
}

fn build_keystore_crypto_context(
    member_id: &str,
    kid: String,
    keystore_root: PathBuf,
    workspace_path: Option<PathBuf>,
    decrypted_key: DecryptedSshKeyData,
) -> Result<CryptoContext> {
    let signing_key = build_signing_key(decrypted_key.private_key.document())?;
    let pub_key_source: Box<dyn PublicKeySource> =
        Box::new(KeystorePublicKeySource::new(keystore_root));

    Ok(CryptoContext {
        member_id: MemberId::try_from(member_id)?,
        kid: Kid::try_from(kid)?,
        pub_key_source,
        workspace_path,
        private_key: decrypted_key.private_key,
        signing_key,
        expires_at: decrypted_key.expires_at,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_context_crypto_test.rs"]
mod feature_context_crypto_test;

#[cfg(test)]
#[path = "../../../tests/unit/feature_context_env_key_integration_test.rs"]
mod feature_context_env_key_integration_test;
