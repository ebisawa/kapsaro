// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation use case.
//! Generates a key pair, stores it in the keystore and activates it.

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::key::github::{resolve_github_account, verify_preflight_github_binding};
use crate::app::key::timestamp::{ensure_expiry_not_reached, resolve_key_timestamps};
use crate::app::key::types::KeyGenerationResult;
use crate::app::verification::OnlineVerificationStatus;
use crate::feature::key::generate::{generate_key, KeyGenerationOptions};
use crate::feature::key::types::KeyGenerationResult as GeneratedKey;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::helpers::find_member_by_kid;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::GithubAccount;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, ErrorKind, Result};

pub(crate) struct AppKeyGenerationOptions {
    pub member_handle: String,
    pub home: KeyGenerationHome,
    pub created_at: String,
    pub expires_at: String,
    pub no_activate: bool,
    pub github_account: Option<GithubAccount>,
    pub github_verification: OnlineVerificationStatus,
    pub ssh_ctx: SshSigningContextResolution,
}

/// The expiry an operator asked for, in whichever of the two forms they used.
///
/// The two arguments are one answer to one question, and only one of them may
/// be given, so they travel together rather than as two values a caller could
/// pass in isolation.
pub struct KeyExpiryRequest<'a> {
    pub expires_at: &'a Option<String>,
    pub valid_for: &'a Option<String>,
}

/// Local state directory a generated key is written into.
///
/// The directory is opened once and handed on as that identity, so the key
/// lands in the directory the command started in rather than in whatever the
/// same path names by the time the key exists.
#[derive(Debug, Clone)]
pub struct KeyGenerationHome(AnchoredDir);

impl KeyGenerationHome {
    /// Fix the local state directory this command writes its key into,
    /// creating it when it is not there yet.
    ///
    /// This is the first thing a key-generating command does. Everything
    /// between here and the write — the member handle, the configuration, the
    /// GitHub binding, the SSH identity — is settled afterwards, and the last
    /// two take an operator at the terminal, which is time enough for the
    /// configured path to come to name a different directory.
    pub fn fix(options: &CommonCommandOptions) -> Result<Self> {
        options.ensure_local_state_home().cloned().map(Self)
    }

    /// Write into a local state directory the caller already opened.
    pub(crate) fn from_opened(home: &AnchoredDir) -> Self {
        Self(home.clone())
    }

    fn ensure_keystore_access(&self) -> Result<KeystoreAccess> {
        KeystoreAccess::create_from_anchored_home(&self.0)
    }
}

pub(crate) struct KeyGenerationSaveResult {
    pub(crate) result: KeyGenerationResult,
    pub(crate) keystore: KeystoreAccess,
}

/// Resolve GitHub account metadata, verify SSH key on GitHub, then generate a key.
fn generate_key_with_github_user(
    mut options: AppKeyGenerationOptions,
    github_user: Option<String>,
) -> Result<KeyGenerationResult> {
    let github_account = resolve_github_account(github_user)?;
    options.github_account = github_account.clone();

    let github_verification = if let Some(account) = github_account.as_ref() {
        verify_preflight_github_binding(&options.ssh_ctx.public_key, account)?
    } else {
        OnlineVerificationStatus::NotConfigured
    };

    options.github_verification = github_verification;
    generate_and_save_key(options)
}

/// Generate one key and store it in the local state directory `home` names.
///
/// The directory arrives already opened rather than as a path to resolve: it is
/// fixed before the command resolves its SSH identity and its GitHub binding,
/// and this is where that identity is spent.
pub fn generate_key_command(
    home: KeyGenerationHome,
    member_handle: String,
    github_user: Option<String>,
    expiry: KeyExpiryRequest<'_>,
    no_activate: bool,
    ssh_ctx: SshSigningContextResolution,
) -> Result<KeyGenerationResult> {
    let (created_at, expires_at) = resolve_key_timestamps(expiry.expires_at, expiry.valid_for)?;

    generate_key_with_github_user(
        AppKeyGenerationOptions {
            member_handle,
            home,
            created_at,
            expires_at,
            no_activate,
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
    generate_and_save_key_with_access(options).map(|saved| saved.result)
}

pub(crate) fn generate_and_save_key_with_access(
    options: AppKeyGenerationOptions,
) -> Result<KeyGenerationSaveResult> {
    let access = options.home.ensure_keystore_access()?;
    let no_activate = options.no_activate;
    let github_verification = options.github_verification;
    let generated = generate_key(KeyGenerationOptions {
        member_handle: options.member_handle,
        created_at: options.created_at,
        expires_at: options.expires_at,
        github_account: options.github_account,
        ssh_binding: options.ssh_ctx.into_ssh_binding(),
    })?;
    ensure_kid_not_in_keystore(&access, &generated.kid)?;
    // Storing the pair is the last thing this command does, so the expiry is
    // settled against this moment rather than against the one the command
    // started at, when the SSH and GitHub steps had not run yet.
    ensure_expiry_not_reached(&generated.expires_at)?;
    save_generated_key(&access, &generated, no_activate)?;
    let result = KeyGenerationResult {
        member_handle: generated.member_handle,
        kid: generated.kid,
        expires_at: generated.expires_at,
        activated: !no_activate,
        ssh_fingerprint: generated.ssh_fingerprint,
        ssh_determinism: generated.ssh_determinism,
        github_verification,
    };
    Ok(KeyGenerationSaveResult {
        result,
        keystore: access,
    })
}

fn ensure_kid_not_in_keystore(access: &KeystoreAccess, kid: &str) -> Result<()> {
    match find_member_by_kid(access, kid) {
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
    access: &KeystoreAccess,
    generated: &GeneratedKey,
    no_activate: bool,
) -> Result<()> {
    let member_handle = MemberHandle::try_from(generated.member_handle.as_str())?;
    let kid = Kid::try_from(generated.kid.as_str())?;
    access.save_key_pair_atomic(
        &member_handle,
        &kid,
        &generated.private_key,
        &generated.public_key,
    )?;
    publish_generated_key(access, &member_handle, &kid, no_activate)
}

/// Point the active marker at the pair that was just stored.
///
/// The keystore stores the pair and publishes the marker under two separate
/// exclusive sections of the member directory. Once the pair is stored it is
/// published state, so an activation failure leaves it available for explicit
/// inspection, retry, or removal.
fn publish_generated_key(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
    kid: &Kid,
    no_activate: bool,
) -> Result<()> {
    if no_activate {
        return Ok(());
    }
    access
        .activate_existing_key(member_handle, kid)
        .map_err(|error| build_activation_failure_error(member_handle, kid, error))
}

/// Add recovery context without changing how the activation failure is handled.
///
/// The error category, validation rule, recovery code, and source belong to the
/// failed activation and remain intact. Only the operator-facing message grows.
fn build_activation_failure_error(
    member_handle: &MemberHandle,
    kid: &Kid,
    activation_error: Error,
) -> Error {
    let message = format!(
        "Generated key '{}' was stored, but activation failed: {}. Run 'kapsaro key list \
         --member-handle {}' to inspect the current active key. After repairing the activation \
         failure, run 'kapsaro key activate {} --member-handle {}' to retry, or 'kapsaro key \
         remove {} --member-handle {}' to remove the stored key.",
        kid,
        activation_error.format_user_message(),
        member_handle,
        kid,
        member_handle,
        kid,
        member_handle
    );
    activation_error.with_message(message)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_key_generate_test.rs"]
mod app_key_generate_test;
