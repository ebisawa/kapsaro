// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::ResolvedCommandPaths;
use crate::app::errors::build_invalid_trust_store_error;
use crate::app::trust::types::TrustMutationResult;
use crate::feature::envelope::signature::build_signing_context;
use crate::feature::envelope::signature::VerifiedSigningContext;
use crate::feature::trust::signature::sign_trust_store;
use crate::feature::trust::verification::verify_trust_store;
use crate::io::trust::paths::trust_store_file_path;
use crate::io::trust::store::{
    load_trust_store, save_trust_store, LoadedTrustStore as IoLoadedTrustStore,
};
use crate::model::identifiers::format::TRUST_LOCAL_V2;
use crate::model::trust_store::TrustStoreProtected;
use crate::support::fs::lock;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

pub(crate) struct LoadedTrustStore {
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
    owner_member_id: &str,
) -> Result<LoadedTrustStore> {
    let loaded = load_trust_store(path, base_dir)
        .map_err(|e| build_invalid_trust_store_error(path, e))?
        .ok_or_else(|| Error::NotFound {
            message: format!("Trust store not found for '{}'", owner_member_id),
        })?;
    verify_loaded_trust_store(path, keystore_root, loaded)
}

pub(crate) fn load_or_build_trust_store(
    path: &Path,
    base_dir: &Path,
    keystore_root: &Path,
    owner_member_id: &str,
) -> Result<LoadedTrustStore> {
    match load_trust_store(path, base_dir).map_err(|e| build_invalid_trust_store_error(path, e))? {
        Some(loaded) => verify_loaded_trust_store(path, keystore_root, loaded),
        None => {
            let now = build_now_timestamp()?;
            Ok(LoadedTrustStore {
                protected: TrustStoreProtected {
                    format: TRUST_LOCAL_V2.to_string(),
                    owner_member_id: owner_member_id.to_string(),
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
    owner_member_id: &str,
) -> Result<PathBuf> {
    let paths = ResolvedCommandPaths::load(options)?;
    Ok(trust_store_file_path(&paths.base_dir, owner_member_id))
}

pub(crate) fn load_optional_trust_store_for_member(
    options: &CommonCommandOptions,
    owner_member_id: &str,
) -> Result<(PathBuf, Option<LoadedTrustStore>)> {
    let paths = ResolvedCommandPaths::load(options)?;
    let path = trust_store_file_path(&paths.base_dir, owner_member_id);
    let loaded = load_trust_store(&path, &paths.base_dir)
        .map_err(|e| build_invalid_trust_store_error(&path, e))?
        .map(|loaded| verify_loaded_trust_store(&path, &paths.keystore_root, loaded))
        .transpose()?;
    Ok((path, loaded))
}

pub(crate) fn load_or_build_trust_store_for_member(
    options: &CommonCommandOptions,
    owner_member_id: &str,
) -> Result<(PathBuf, LoadedTrustStore)> {
    let paths = ResolvedCommandPaths::load(options)?;
    let path = trust_store_file_path(&paths.base_dir, owner_member_id);
    let loaded = load_or_build_trust_store(
        &path,
        &paths.base_dir,
        &paths.keystore_root,
        owner_member_id,
    )?;
    Ok((path, loaded))
}

pub(crate) fn sign_and_save_trust_store(
    path: &Path,
    protected: &TrustStoreProtected,
    signing: &VerifiedSigningContext<'_>,
) -> Result<()> {
    let document = sign_trust_store(protected, signing.signing_key(), signing.signer_kid())?;
    save_trust_store(path, &document)
}

pub(crate) fn mutate_trust_store<T, F>(
    path: &Path,
    keystore_root: &Path,
    owner_member_id: &str,
    mode: TrustStoreMutationMode,
    signing: &VerifiedSigningContext<'_>,
    mutate: F,
) -> Result<TrustMutationResult<T>>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    lock::with_file_lock(path, || {
        let loaded =
            match mode {
                TrustStoreMutationMode::ExistingRequired => {
                    let base_dir = path.parent().and_then(|dir| dir.parent()).ok_or_else(|| {
                        Error::Config {
                            message: format!("Invalid trust store path '{}'", path.display()),
                        }
                    })?;
                    load_existing_trust_store(path, base_dir, keystore_root, owner_member_id)?
                }
                TrustStoreMutationMode::CreateIfMissing => {
                    let base_dir = path.parent().and_then(|dir| dir.parent()).ok_or_else(|| {
                        Error::Config {
                            message: format!("Invalid trust store path '{}'", path.display()),
                        }
                    })?;
                    load_or_build_trust_store(path, base_dir, keystore_root, owner_member_id)?
                }
            };
        let mut protected = loaded.protected;
        let mutation = mutate(&mut protected)?;

        if mutation.changed {
            protected.updated_at = build_now_timestamp()?;
            sign_and_save_trust_store(path, &protected, signing)?;
        }

        Ok(TrustMutationResult::new(mutation.value, loaded.warnings))
    })
}

pub(crate) fn mutate_trust_store_with_execution<T, F>(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    mode: TrustStoreMutationMode,
    debug: bool,
    mutate: F,
) -> Result<TrustMutationResult<T>>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    let path = resolve_trust_store_path(options, &execution.member_id)?;
    let keystore_root = options.resolve_keystore_root()?;
    let signing = build_signing_context(&execution.key_ctx, debug)?;
    mutate_trust_store(
        &path,
        &keystore_root,
        &execution.member_id,
        mode,
        &signing,
        mutate,
    )
}

pub(crate) fn build_now_timestamp() -> Result<String> {
    crate::support::time::build_timestamp_display(time::OffsetDateTime::now_utc())
}

fn verify_loaded_trust_store(
    path: &Path,
    keystore_root: &Path,
    loaded: IoLoadedTrustStore,
) -> Result<LoadedTrustStore> {
    let warnings = loaded.permission_warnings;
    let verified = verify_trust_store(&loaded.document, keystore_root)
        .map_err(|e| build_invalid_trust_store_error(path, e))?;
    let (doc, _) = verified.into_inner();
    Ok(LoadedTrustStore {
        protected: doc.protected,
        warnings,
    })
}
