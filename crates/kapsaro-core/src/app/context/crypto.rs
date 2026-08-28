// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Crypto context construction for command execution.
//! Loads the local key from the keystore or from the environment key.

use std::path::PathBuf;

use tracing::debug;

#[cfg(test)]
use crate::feature::context::crypto::load_crypto_context_from_keystore;
use crate::feature::context::crypto::{
    build_signing_key, load_crypto_context_from_keystore_with_selected_kid, CryptoContext,
};
use crate::feature::context::expiry::LocalKeyPairExpiry;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::public_key_source::WorkspacePublicKeySource;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identity::{Kid, MemberHandle};
use crate::Result;

#[cfg(test)]
pub(crate) fn load_crypto_context_with_access(
    access: KeystoreAccess,
    member_handle: MemberHandle,
    backend: Box<dyn SignatureBackend>,
    ssh_pubkey: String,
    explicit_kid: Option<&str>,
    workspace_path: Option<PathBuf>,
) -> Result<CryptoContext> {
    log_crypto_context_load(member_handle.as_str(), explicit_kid);
    load_crypto_context_from_keystore(
        access,
        member_handle,
        explicit_kid,
        backend,
        ssh_pubkey,
        workspace_path,
    )
}

pub(crate) fn load_crypto_context_with_selected_kid(
    access: KeystoreAccess,
    member_handle: MemberHandle,
    backend: Box<dyn SignatureBackend>,
    ssh_pubkey: String,
    selected_kid: Kid,
    selected_kid_override: bool,
    workspace_path: Option<PathBuf>,
) -> Result<CryptoContext> {
    log_crypto_context_load(member_handle.as_str(), Some(selected_kid.as_str()));
    load_crypto_context_from_keystore_with_selected_kid(
        access,
        member_handle,
        selected_kid,
        selected_kid_override,
        backend,
        ssh_pubkey,
        workspace_path,
    )
}

pub fn load_crypto_context_from_env(workspace_path: PathBuf) -> Result<CryptoContext> {
    let result = crate::feature::context::env_key::load_private_key_from_env()?;
    let kid = Kid::try_from(result.verified_key.proof().kid().to_string())?;
    let signing_key = build_signing_key(result.verified_key.document())?;
    let context = CryptoContext::new(
        result.member_handle,
        kid,
        Box::new(WorkspacePublicKeySource::new(workspace_path.clone())),
        Some(workspace_path),
        result.verified_key,
        signing_key,
        LocalKeyPairExpiry::from_private_key(result.expires_at),
    );
    Ok(context.with_local_key_access(None, None))
}

fn log_crypto_context_load(member_handle: &str, explicit_kid: Option<&str>) {
    debug!(
        "[CRYPTO] load_crypto_context: member_handle={}, explicit_kid={}",
        member_handle,
        explicit_kid.unwrap_or("(none)")
    );
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_crypto_test.rs"]
mod feature_context_crypto_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_env_key_integration_test.rs"]
mod feature_context_env_key_integration_test;
