// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use tracing::debug;

use crate::feature::context::crypto::{
    build_local_key_access, build_signing_key, load_verified_private_key_from_keystore,
    CryptoContext,
};
use crate::feature::context::expiry::VerifiedExpiresAt;
use crate::io::config::paths::get_base_dir;
use crate::io::keystore::helpers::resolve_kid;
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::io::keystore::public_key_source::{
    KeystorePublicKeySource, PublicKeySource, WorkspacePublicKeySource,
};
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identity::{Kid, MemberHandle};
use crate::support::kid::format_kid_display;
use crate::Result;

pub fn load_crypto_context(
    member_handle: &str,
    backend: Box<dyn SignatureBackend>,
    ssh_pubkey: String,
    explicit_kid: Option<&str>,
    keystore_root: Option<&PathBuf>,
    workspace_path: Option<PathBuf>,
    debug_enabled: bool,
) -> Result<CryptoContext> {
    log_crypto_context_load(member_handle, explicit_kid, debug_enabled);
    let keystore_root = resolve_keystore_root(keystore_root)?;
    let kid = resolve_keystore_kid(&keystore_root, member_handle, explicit_kid, debug_enabled)?;
    let decrypted_key = load_verified_private_key_from_keystore(
        &keystore_root,
        member_handle,
        &kid,
        backend.as_ref(),
        &ssh_pubkey,
        debug_enabled,
    )?;
    let selected_kid_override = explicit_kid
        .map(|_| Kid::try_from(decrypted_key.private_key.proof().kid().to_string()))
        .transpose()?;
    let local_key_access = build_local_key_access(keystore_root.clone(), ssh_pubkey, backend);
    let context = build_keystore_crypto_context(
        member_handle,
        kid,
        keystore_root,
        workspace_path,
        decrypted_key.private_key,
        decrypted_key.expires_at,
    )?;
    Ok(context.with_local_key_access(selected_kid_override, Some(local_key_access)))
}

pub fn load_crypto_context_from_env(
    workspace_path: PathBuf,
    debug_enabled: bool,
) -> Result<CryptoContext> {
    let result = crate::feature::context::env_key::load_private_key_from_env(debug_enabled)?;
    let kid = Kid::try_from(result.verified_key.proof().kid().to_string())?;
    let signing_key = build_signing_key(result.verified_key.document())?;
    let context = CryptoContext::new(
        result.member_handle,
        kid,
        Box::new(WorkspacePublicKeySource::new(workspace_path.clone())),
        Some(workspace_path),
        result.verified_key,
        signing_key,
        result.expires_at,
    );
    Ok(context.with_local_key_access(None, None))
}

fn log_crypto_context_load(member_handle: &str, explicit_kid: Option<&str>, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[CRYPTO] load_crypto_context: member_handle={}, explicit_kid={}",
            member_handle,
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

fn build_keystore_crypto_context(
    member_handle: &str,
    kid: String,
    keystore_root: PathBuf,
    workspace_path: Option<PathBuf>,
    private_key: crate::model::verified::VerifiedPrivateKey,
    expires_at: VerifiedExpiresAt,
) -> Result<CryptoContext> {
    let signing_key = build_signing_key(private_key.document())?;
    let pub_key_source: Box<dyn PublicKeySource> =
        Box::new(KeystorePublicKeySource::new(keystore_root.clone()));

    let context = CryptoContext::new(
        MemberHandle::try_from(member_handle)?,
        Kid::try_from(kid)?,
        pub_key_source,
        workspace_path,
        private_key,
        signing_key,
        expires_at,
    );
    Ok(context)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_crypto_test.rs"]
mod feature_context_crypto_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_env_key_integration_test.rs"]
mod feature_context_env_key_integration_test;
