// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation (key new) implementation

use crate::cli::common::command::{resolve_options, resolve_required_member_handle};
use crate::cli::common::output::text::key::{
    print_generated_key_summary, print_key_generation_binding_info,
};
use crate::cli::common::ssh::resolve_ssh_context;
use crate::cli::identity_prompt::resolve_key_generation_github_user;
use kapsaro_core::cli_api::app::key::generate::generate_key_command;
use kapsaro_core::Result;

use super::NewArgs;

/// Main entry point for key generation
pub(super) fn run(args: NewArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    let member_handle =
        resolve_required_member_handle(&options, args.member.member_handle.clone(), true)?;
    let github_user = resolve_key_generation_github_user(
        true,
        args.github_user.clone(),
        options.home.as_deref(),
    )?;
    eprintln!();
    let ssh_ctx = resolve_ssh_context(&options)?;
    let result = generate_key_command(
        &options,
        member_handle,
        github_user,
        &args.expires_at,
        &args.valid_for,
        args.no_activate,
        ssh_ctx,
    )?;

    print_key_generation_binding_info(
        &result.ssh_fingerprint,
        &result.ssh_determinism,
        result.github_verification,
    )?;
    print_generated_key_summary(
        &result.member_handle,
        &result.kid,
        &result.expires_at,
        result.activated,
    );

    Ok(())
}
