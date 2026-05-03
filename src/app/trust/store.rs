// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::CommandPathResolution;
use crate::app::errors::build_invalid_trust_store_error;
use crate::app::trust::types::TrustMutationResult;
use crate::feature::envelope::signature::build_signing_context;
use crate::feature::envelope::signature::VerifiedSigningContext;
use crate::feature::trust::signature::sign_trust_store;
use crate::feature::trust::verification::verify_trust_store;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::{
    load_trust_store, save_trust_store, TrustStoreLoadResult as IoTrustStoreLoadResult,
};
use crate::model::identifiers::format::TRUST_LOCAL_V3;
use crate::model::trust_store::TrustStoreProtected;
use crate::support::fs::lock;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

pub(crate) struct TrustStoreState {
    pub(crate) protected: TrustStoreProtected,
    pub(crate) warnings: Vec<String>,
}

pub(crate) enum TrustStoreMutationMode {
    ExistingRequired,
    CreateIfMissing,
}

pub(crate) struct TrustStoreMutation<T> {
    pub(crate) value: T,
    pub(crate) changed: bool,
}

pub(crate) fn load_existing_trust_store(
    path: &Path,
    base_dir: &Path,
    keystore_root: &Path,
    owner_handle: &str,
) -> Result<TrustStoreState> {
    let loaded = load_trust_store(path, base_dir)
        .map_err(|e| build_invalid_trust_store_error(path, e))?
        .ok_or_else(|| Error::NotFound {
            message: format!("Trust store not found for '{}'", owner_handle),
        })?;
    verify_loaded_trust_store(path, keystore_root, loaded)
}

pub(crate) fn load_or_build_trust_store(
    path: &Path,
    base_dir: &Path,
    keystore_root: &Path,
    owner_handle: &str,
) -> Result<TrustStoreState> {
    match load_trust_store(path, base_dir).map_err(|e| build_invalid_trust_store_error(path, e))? {
        Some(loaded) => verify_loaded_trust_store(path, keystore_root, loaded),
        None => {
            let now = build_now_timestamp()?;
            Ok(TrustStoreState {
                protected: TrustStoreProtected {
                    format: TRUST_LOCAL_V3.to_string(),
                    owner_handle: owner_handle.to_string(),
                    created_at: now.clone(),
                    updated_at: now,
                    known_keys: Vec::new(),
                },
                warnings: Vec::new(),
            })
        }
    }
}

pub(crate) fn resolve_trust_store_path(
    options: &CommonCommandOptions,
    owner_handle: &str,
) -> Result<PathBuf> {
    let paths = CommandPathResolution::load(options)?;
    Ok(get_trust_store_file_path(&paths.base_dir, owner_handle))
}

pub(crate) fn load_optional_trust_store_for_member(
    options: &CommonCommandOptions,
    owner_handle: &str,
) -> Result<(PathBuf, Option<TrustStoreState>)> {
    let paths = CommandPathResolution::load(options)?;
    let path = get_trust_store_file_path(&paths.base_dir, owner_handle);
    let loaded = load_trust_store(&path, &paths.base_dir)
        .map_err(|e| build_invalid_trust_store_error(&path, e))?
        .map(|loaded| verify_loaded_trust_store(&path, &paths.keystore_root, loaded))
        .transpose()?;
    Ok((path, loaded))
}

pub(crate) fn load_or_build_trust_store_for_member(
    options: &CommonCommandOptions,
    owner_handle: &str,
) -> Result<(PathBuf, TrustStoreState)> {
    let paths = CommandPathResolution::load(options)?;
    let path = get_trust_store_file_path(&paths.base_dir, owner_handle);
    let loaded =
        load_or_build_trust_store(&path, &paths.base_dir, &paths.keystore_root, owner_handle)?;
    Ok((path, loaded))
}

pub(crate) fn save_signed_trust_store(
    path: &Path,
    protected: &TrustStoreProtected,
    signing: &VerifiedSigningContext<'_>,
) -> Result<()> {
    let document = sign_trust_store(protected, signing.signing_key(), signing.signer_kid())?;
    save_trust_store(path, &document)
}

pub(crate) fn execute_trust_store_mutation<T, F>(
    path: &Path,
    keystore_root: &Path,
    owner_handle: &str,
    mode: TrustStoreMutationMode,
    signing: &VerifiedSigningContext<'_>,
    mutate: F,
) -> Result<TrustMutationResult<T>>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    lock::with_file_lock(path, || {
        let loaded = load_trust_store_for_mutation(path, keystore_root, owner_handle, mode)?;
        let mut protected = loaded.protected;
        let mutation = mutate(&mut protected)?;

        save_changed_trust_store(path, &mut protected, signing, mutation.changed)?;

        Ok(TrustMutationResult::new(mutation.value, loaded.warnings))
    })
}

pub(crate) fn execute_trust_store_mutation_with_execution<T, F>(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
    debug: bool,
    mutate: F,
) -> Result<TrustMutationResult<T>>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    let path = resolve_trust_store_path(options, &execution.member_handle)?;
    let keystore_root = options.resolve_keystore_root()?;
    let signing = build_signing_context(&execution.key_ctx, debug)?;
    execute_trust_store_mutation(
        &path,
        &keystore_root,
        &execution.member_handle,
        mode,
        &signing,
        mutate,
    )
}

pub(crate) fn build_now_timestamp() -> Result<String> {
    crate::support::time::format_timestamp_rfc3339(time::OffsetDateTime::now_utc())
}

fn load_trust_store_for_mutation(
    path: &Path,
    keystore_root: &Path,
    owner_handle: &str,
    mode: TrustStoreMutationMode,
) -> Result<TrustStoreState> {
    let base_dir = resolve_trust_store_base_dir(path)?;
    match mode {
        TrustStoreMutationMode::ExistingRequired => {
            load_existing_trust_store(path, base_dir, keystore_root, owner_handle)
        }
        TrustStoreMutationMode::CreateIfMissing => {
            load_or_build_trust_store(path, base_dir, keystore_root, owner_handle)
        }
    }
}

fn resolve_trust_store_base_dir(path: &Path) -> Result<&Path> {
    path.parent().and_then(|dir| dir.parent()).ok_or_else(|| {
        Error::build_config_error(format!("Invalid trust store path '{}'", path.display()))
    })
}

fn save_changed_trust_store(
    path: &Path,
    protected: &mut TrustStoreProtected,
    signing: &VerifiedSigningContext<'_>,
    changed: bool,
) -> Result<()> {
    if !changed {
        return Ok(());
    }
    protected.updated_at = build_now_timestamp()?;
    save_signed_trust_store(path, protected, signing)
}

fn verify_loaded_trust_store(
    path: &Path,
    keystore_root: &Path,
    loaded: IoTrustStoreLoadResult,
) -> Result<TrustStoreState> {
    let warnings = loaded.permission_warnings;
    let verified = verify_trust_store(&loaded.document, keystore_root)
        .map_err(|e| build_invalid_trust_store_error(path, e))?;
    let (doc, _) = verified.into_inner();
    Ok(TrustStoreState {
        protected: doc.protected,
        warnings,
    })
}
