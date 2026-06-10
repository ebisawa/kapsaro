// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application orchestration for local key management commands.
//! Resolves command context, keystore paths, and key I/O before feature calls.

use std::path::Path;

use crate::app::context::member::{resolve_key_owner, resolve_required_member};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::key::build_no_active_key_error;
use crate::app::key::export::save_exported_public_key;
use crate::app::key::types::{
    KeyActivateResult, KeyExportPrivateResult, KeyExportResult, KeyInfo, KeyListResult,
    KeyRemoveResult,
};
use crate::feature::key::material::validate_private_key_material;
use crate::feature::key::portable_export::{
    build_password_strength_warning, export_private_key_portable, validate_export_password,
    ExportPasswordPolicy, PortableExportOptions,
};
use crate::feature::key::protection::encryption::decrypt_private_key;
use crate::feature::verify::private_key::verify_private_key_matches_public_key;
use crate::feature::verify::public_key::{
    verify_public_key_with_attestation_context, KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT,
};
use crate::io::keystore::active::{clear_active_kid, load_active_kid, set_active_kid};
use crate::io::keystore::helpers::resolve_member_kid_query;
use crate::io::keystore::member::{remove_key_directory, select_latest_valid_kid};
use crate::io::keystore::paths::get_private_key_file_path_from_root;
use crate::io::keystore::storage::{
    list_kids, list_member_handles, load_private_key, load_public_key,
};
use crate::io::ssh::backend::SignatureBackend;
use crate::model::private_key::PrivateKeyPlaintext;
use crate::support::secret::SecretString;
use crate::{Error, Result};

pub fn list_keys_command(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<KeyListResult> {
    let keystore_root = options.resolve_keystore_root()?;
    let member_handles = resolve_member_handles(&keystore_root, member_handle)?;
    let entries = load_key_infos(&keystore_root, &member_handles)?;
    let total_keys = entries.iter().map(|(_, keys)| keys.len()).sum();

    Ok(KeyListResult {
        entries,
        total_keys,
    })
}

pub fn activate_key_command(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    kid: Option<String>,
) -> Result<KeyActivateResult> {
    let member_handle = resolve_required_member(options, member_handle)?;
    let keystore_root = options.resolve_keystore_root()?;
    let kid = resolve_activated_kid(&keystore_root, &member_handle, kid)?;
    validate_key_exists(&keystore_root, &member_handle, &kid)?;
    set_active_kid(&member_handle, &kid, &keystore_root)?;
    Ok(KeyActivateResult { member_handle, kid })
}

pub fn remove_key_command(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    kid: String,
    force: bool,
) -> Result<KeyRemoveResult> {
    let resolved_member_handle = resolve_key_owner(options, member_handle, &kid)?;
    let keystore_root = options.resolve_keystore_root()?;
    let kid = resolve_member_kid_query(&keystore_root, &resolved_member_handle, &kid)?;
    validate_key_directory_exists(&keystore_root, &resolved_member_handle, &kid)?;
    let was_active =
        load_active_kid(&resolved_member_handle, &keystore_root)?.as_ref() == Some(&kid);
    validate_key_removal(&kid, was_active, force)?;
    remove_key_directory(&keystore_root, &resolved_member_handle, &kid)?;

    if was_active {
        clear_active_kid(&resolved_member_handle, &keystore_root)?;
    }

    Ok(KeyRemoveResult {
        member_handle: resolved_member_handle,
        kid,
        was_active,
    })
}

pub fn export_key_command(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    kid: Option<String>,
    out: &Path,
) -> Result<KeyExportResult> {
    let member_handle = resolve_required_member(options, member_handle)?;
    let keystore_root = options.resolve_keystore_root()?;
    let kid = resolve_active_kid(&keystore_root, &member_handle, kid)?;
    let public_key = load_public_key(&keystore_root, &member_handle, &kid)?;
    let result = KeyExportResult {
        member_handle,
        kid,
        public_key,
    };
    save_exported_public_key(out, &result.public_key)?;
    Ok(result)
}

/// Validate that the specified KID exists before expensive operations.
pub fn validate_kid(
    options: &CommonCommandOptions,
    member_handle: &str,
    kid: Option<String>,
) -> Result<()> {
    let keystore_root = options.resolve_keystore_root()?;
    resolve_active_kid(&keystore_root, member_handle, kid)?;
    Ok(())
}

pub fn export_private_key_command(
    options: &CommonCommandOptions,
    member_handle: String,
    kid: Option<String>,
    password: &SecretString,
    allow_weak_password: bool,
    ssh_ctx: SshSigningContextResolution,
) -> Result<KeyExportPrivateResult> {
    let password_policy = export_password_policy(allow_weak_password);
    validate_export_password(password.as_str(), password_policy)?;

    let keystore_root = options.resolve_keystore_root()?;
    let kid = resolve_active_kid(&keystore_root, &member_handle, kid)?;
    let loaded = load_private_key_export_material(
        &keystore_root,
        member_handle,
        kid,
        ssh_ctx.backend.as_ref(),
        &ssh_ctx.public_key,
        options.debug,
    )?;

    let encoded_key = export_private_key_portable(
        &loaded.plaintext,
        &loaded.member_handle,
        &loaded.kid,
        &loaded.created_at,
        &loaded.expires_at,
        password,
        PortableExportOptions::new(password_policy, options.debug),
    )?;

    Ok(crate::feature::key::portable_export::PortableExportOutput {
        member_handle: loaded.member_handle,
        kid: loaded.kid,
        encoded_key,
        password_warning: build_export_password_warning(password.as_str(), allow_weak_password),
    }
    .into())
}

fn export_password_policy(allow_weak_password: bool) -> ExportPasswordPolicy {
    if allow_weak_password {
        ExportPasswordPolicy::AllowWeak
    } else {
        ExportPasswordPolicy::Recommended
    }
}

fn build_export_password_warning(password: &str, allow_weak_password: bool) -> Option<String> {
    allow_weak_password
        .then(|| build_password_strength_warning(password))
        .flatten()
}

struct PrivateKeyExportMaterial {
    plaintext: PrivateKeyPlaintext,
    member_handle: String,
    kid: String,
    created_at: String,
    expires_at: String,
}

fn resolve_member_handles(
    keystore_root: &Path,
    member_handle: Option<String>,
) -> Result<Vec<String>> {
    match member_handle {
        Some(member_handle) => Ok(vec![member_handle]),
        None => list_member_handles(keystore_root),
    }
}

fn load_key_infos(
    keystore_root: &Path,
    member_handles: &[String],
) -> Result<Vec<(String, Vec<KeyInfo>)>> {
    member_handles
        .iter()
        .map(|member_handle| load_member_key_infos(keystore_root, member_handle))
        .collect()
}

fn load_member_key_infos(
    keystore_root: &Path,
    member_handle: &str,
) -> Result<(String, Vec<KeyInfo>)> {
    let kids = list_kids(keystore_root, member_handle)?;
    let active_kid = load_active_kid(member_handle, keystore_root)?;
    let key_infos = kids
        .iter()
        .map(|kid| load_key_info(keystore_root, member_handle, kid, active_kid.as_deref()))
        .collect::<Result<Vec<_>>>()?;

    Ok((member_handle.to_string(), key_infos))
}

fn load_key_info(
    keystore_root: &Path,
    member_handle: &str,
    kid: &str,
    active_kid: Option<&str>,
) -> Result<KeyInfo> {
    let public_key = load_public_key(keystore_root, member_handle, kid)?;
    Ok(KeyInfo {
        kid: kid.to_string(),
        member_handle: public_key.protected.subject_handle.clone(),
        created_at: public_key.protected.created_at.clone().unwrap_or_default(),
        expires_at: public_key.protected.expires_at.clone(),
        active: active_kid == Some(kid),
        format: public_key.protected.format.clone(),
    })
}

fn resolve_active_kid(
    keystore_root: &Path,
    member_handle: &str,
    kid: Option<String>,
) -> Result<String> {
    match kid {
        Some(kid) => resolve_member_kid_query(keystore_root, member_handle, &kid),
        None => load_active_kid(member_handle, keystore_root)?
            .ok_or_else(|| build_no_active_key_error(member_handle)),
    }
}

fn load_private_key_export_material(
    keystore_root: &Path,
    member_handle: String,
    kid: String,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    debug: bool,
) -> Result<PrivateKeyExportMaterial> {
    let encrypted = load_private_key(keystore_root, &member_handle, &kid)?;
    let public_key = load_public_key(keystore_root, &member_handle, &kid)?;
    let verified_public_key = verify_public_key_with_attestation_context(
        &public_key,
        debug,
        KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT,
    )?;
    verify_private_key_matches_public_key(&encrypted, verified_public_key.document())?;

    let plaintext = decrypt_private_key(&encrypted, backend, ssh_pubkey, debug)?;
    validate_private_key_material(&plaintext)?;

    Ok(PrivateKeyExportMaterial {
        plaintext,
        member_handle,
        kid,
        created_at: encrypted.protected.created_at.clone(),
        expires_at: encrypted.protected.expires_at.clone(),
    })
}

fn resolve_activated_kid(
    keystore_root: &Path,
    member_handle: &str,
    kid: Option<String>,
) -> Result<String> {
    match kid {
        Some(kid) => resolve_member_kid_query(keystore_root, member_handle, &kid),
        None => select_latest_valid_kid(keystore_root, member_handle),
    }
}

fn validate_key_exists(keystore_root: &Path, member_handle: &str, kid: &str) -> Result<()> {
    let private_key_path = get_private_key_file_path_from_root(keystore_root, member_handle, kid);
    if private_key_path.exists() {
        return Ok(());
    }

    Err(Error::build_not_found_error(format!(
        "Key not found: {}",
        kid
    )))
}

fn validate_key_directory_exists(
    keystore_root: &Path,
    member_handle: &str,
    kid: &str,
) -> Result<()> {
    let key_dir = keystore_root.join(member_handle).join(kid);
    if key_dir.exists() {
        return Ok(());
    }

    Err(Error::build_not_found_error(format!(
        "Key not found: {}",
        kid
    )))
}

fn validate_key_removal(kid: &str, was_active: bool, force: bool) -> Result<()> {
    if !was_active || force {
        return Ok(());
    }

    Err(Error::build_config_error(format!(
        "Cannot remove active key '{}'. Use --force to remove anyway.",
        kid
    )))
}
