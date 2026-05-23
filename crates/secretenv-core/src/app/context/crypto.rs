// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use tracing::debug;

use crate::feature::context::crypto::{
    build_signing_key, load_crypto_context_from_keystore, CryptoContext,
};
use crate::io::config::paths::get_base_dir;
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::io::keystore::public_key_source::WorkspacePublicKeySource;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identity::Kid;
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
    load_crypto_context_from_keystore(
        keystore_root,
        member_handle,
        explicit_kid,
        backend,
        ssh_pubkey,
        workspace_path,
        debug_enabled,
    )
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

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_crypto_test.rs"]
mod feature_context_crypto_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_env_key_integration_test.rs"]
mod feature_context_env_key_integration_test;
