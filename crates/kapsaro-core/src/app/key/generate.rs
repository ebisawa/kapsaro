// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::identity::resolve_github_user_input;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::key::github::{resolve_github_account, verify_preflight_github_binding};
use crate::app::key::timestamp::resolve_key_timestamps;
use crate::app::key::types::KeyGenerationResult;
use crate::app::verification::OnlineVerificationStatus;
use crate::feature::key::generate::{generate_key, KeyGenerationOptions};
use crate::io::keystore::active::set_active_kid;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::keystore::storage::{find_member_by_kid, save_key_pair_atomic};
use crate::model::public_key::GithubAccount;
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

pub(crate) struct AppKeyGenerationOptions {
    pub member_handle: String,
    pub home: Option<PathBuf>,
    pub created_at: String,
    pub expires_at: String,
    pub no_activate: bool,
    pub debug: bool,
    pub github_account: Option<GithubAccount>,
    pub github_verification: OnlineVerificationStatus,
    pub ssh_ctx: SshSigningContextResolution,
}

/// Resolve GitHub account metadata, verify SSH key on GitHub, then generate a key.
fn generate_key_with_github_user(
    mut options: AppKeyGenerationOptions,
    github_user: Option<String>,
) -> Result<KeyGenerationResult> {
    let github_account = resolve_github_account(github_user, options.debug)?;
    options.github_account = github_account.clone();

    let github_verification = if let Some(account) = github_account.as_ref() {
        verify_preflight_github_binding(&options.ssh_ctx.public_key, account, options.debug)?
    } else {
        OnlineVerificationStatus::NotConfigured
    };

    options.github_verification = github_verification;
    generate_and_save_key(options)
}

pub fn generate_key_command(
    options: &CommonCommandOptions,
    member_handle: String,
    github_user_arg: Option<String>,
    expires_at_arg: &Option<String>,
    valid_for_arg: &Option<String>,
    no_activate: bool,
    ssh_ctx: SshSigningContextResolution,
) -> Result<KeyGenerationResult> {
    let github_user = resolve_github_user_input(github_user_arg, options.home.as_deref())?;
    let (created_at, expires_at) = resolve_key_timestamps(expires_at_arg, valid_for_arg)?;

    generate_key_with_github_user(
        AppKeyGenerationOptions {
            member_handle,
            home: options.home.clone(),
            created_at,
            expires_at,
            no_activate,
            debug: options.debug,
            github_account: None,
            github_verification: OnlineVerificationStatus::NotConfigured,
            ssh_ctx,
        },
        github_user,
    )
}

pub(crate) fn generate_and_save_key(
    options: AppKeyGenerationOptions,
) -> Result<KeyGenerationResult> {
    let keystore_root = ensure_keystore_dir(&options.home)?;
    let no_activate = options.no_activate;
    let github_verification = options.github_verification;
    let generated = generate_key(KeyGenerationOptions {
        member_handle: options.member_handle,
        created_at: options.created_at,
        expires_at: options.expires_at,
        debug: options.debug,
        github_account: options.github_account,
        ssh_binding: options.ssh_ctx.into_ssh_binding(),
    })?;
    ensure_kid_not_in_keystore(&keystore_root, &generated.kid)?;
    save_generated_key(&keystore_root, &generated, no_activate)?;
    Ok(KeyGenerationResult {
        member_handle: generated.member_handle,
        kid: generated.kid,
        expires_at: generated.expires_at,
        activated: !no_activate,
        ssh_fingerprint: generated.ssh_fingerprint,
        ssh_determinism: generated.ssh_determinism,
        github_verification,
    })
}

fn ensure_keystore_dir(home: &Option<PathBuf>) -> Result<PathBuf> {
    KeystoreResolver::ensure_keystore_root(home.as_ref())
}

fn ensure_kid_not_in_keystore(keystore_root: &Path, kid: &str) -> Result<()> {
    match find_member_by_kid(keystore_root, kid) {
        Ok(owner_handle) => Err(Error::build_crypto_error(format!(
            "kid '{}' already exists in keystore (member_handle: '{}')",
            format_kid_display_lossy(kid),
            owner_handle
        ))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn save_generated_key(
    keystore_root: &Path,
    generated: &crate::feature::key::types::KeyGenerationResult,
    no_activate: bool,
) -> Result<()> {
    save_key_pair_atomic(
        keystore_root,
        &generated.member_handle,
        &generated.kid,
        &generated.private_key,
        &generated.public_key,
    )?;
    if !no_activate {
        set_active_kid(&generated.member_handle, &generated.kid, keystore_root)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_key_generate_test.rs"]
mod tests;
