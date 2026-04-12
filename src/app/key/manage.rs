// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::member::{resolve_key_owner, resolve_required_member};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::ResolvedSshSigningContext;
use crate::app::key::export::save_exported_public_key;
use crate::app::key::types::{KeyExportPrivateResult, KeyListResult};
use crate::feature::key::manage::common::{resolve_active_kid, resolve_keystore_root};
use crate::feature::key::manage::export::export_key;
use crate::feature::key::manage::mutation::{activate_key, remove_key};
use crate::feature::key::manage::private_load::load_and_decrypt_private_key;
use crate::feature::key::manage::query::list_keys;
use crate::feature::key::portable_export::export_private_key_portable;
use crate::feature::key::types::{KeyActivateResult, KeyExportResult, KeyRemoveResult};
use crate::Result;

pub fn list_keys_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
) -> Result<KeyListResult> {
    list_keys(options.home.clone(), member_id).map(Into::into)
}

pub fn activate_key_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: Option<String>,
) -> Result<KeyActivateResult> {
    let member_id = resolve_required_member(options, member_id)?;
    activate_key(options.home.clone(), member_id, kid)
}

pub fn remove_key_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: String,
    force: bool,
) -> Result<KeyRemoveResult> {
    let resolved_member_id = resolve_key_owner(options, member_id, &kid)?;
    remove_key(options.home.clone(), resolved_member_id, kid, force)
}

pub fn export_key_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: Option<String>,
    out: &Path,
) -> Result<KeyExportResult> {
    let member_id = resolve_required_member(options, member_id)?;
    let result = export_key(options.home.clone(), member_id, kid)?;
    save_exported_public_key(out, &result.public_key)?;
    Ok(result)
}

/// Validate that the specified KID exists before expensive operations.
pub fn validate_kid(
    options: &CommonCommandOptions,
    member_id: &str,
    kid: Option<String>,
) -> Result<()> {
    let keystore_root = resolve_keystore_root(options.home.clone())?;
    resolve_active_kid(&keystore_root, member_id, kid)?;
    Ok(())
}

pub fn export_private_key_command(
    options: &CommonCommandOptions,
    member_id: String,
    kid: Option<String>,
    password: &str,
    ssh_ctx: ResolvedSshSigningContext,
) -> Result<KeyExportPrivateResult> {
    let loaded = load_and_decrypt_private_key(
        options.home.clone(),
        member_id,
        kid,
        ssh_ctx.backend.as_ref(),
        &ssh_ctx.public_key,
        options.verbose,
    )?;

    let encoded_key = export_private_key_portable(
        &loaded.plaintext,
        &loaded.member_id,
        &loaded.kid,
        &loaded.created_at,
        &loaded.expires_at,
        password,
        options.verbose,
    )?;

    Ok(crate::feature::key::portable_export::PortableExportOutput {
        member_id: loaded.member_id,
        kid: loaded.kid,
        encoded_key,
    }
    .into())
}
