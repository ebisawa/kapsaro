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
use crate::Result;

/// Resolve GitHub account metadata, verify SSH key on GitHub, then generate a key.
fn generate_key_with_github_user(
    mut options: KeyGenerationOptions,
    github_user: Option<String>,
) -> Result<KeyGenerationResult> {
    let github_account = resolve_github_account(github_user, options.verbose)?;
    options.github_account = github_account.clone();

    let github_verification = if let Some(account) = github_account.as_ref() {
        verify_preflight_github_binding(&options.ssh_binding.public_key, account, options.verbose)?
            .into()
    } else {
        OnlineVerificationStatus::NotConfigured
    };

    let result = generate_key(options)?;
    let mut key_result: KeyGenerationResult = result.into();
    key_result.github_verification = github_verification;
    Ok(key_result)
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
        KeyGenerationOptions {
            member_handle,
            home: options.home.clone(),
            created_at,
            expires_at,
            no_activate,
            debug: options.verbose,
            github_account: None,
            verbose: options.verbose,
            ssh_binding: ssh_ctx.into_ssh_binding(),
        },
        github_user,
    )
}
