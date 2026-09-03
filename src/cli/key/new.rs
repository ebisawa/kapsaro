// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation (key new) implementation

use crate::cli::common::command::resolve_required_cli_member_handle;
use crate::cli::common::context::CliContext;
use crate::cli::common::output::text::key::{
    print_generated_key_summary, print_key_generation_binding_info,
};
use crate::cli::common::ssh::resolve_ssh_context;
use crate::cli::identity_prompt::resolve_cli_key_generation_github_user;
use kapsaro_core::api::key::generate::{generate_key_command, KeyExpiryRequest, KeyGenerationHome};
use kapsaro_core::Result;

use super::NewArgs;

/// Main entry point for key generation
pub(super) fn run(args: NewArgs) -> Result<()> {
    let context = CliContext::resolve(&args.common)?;
    // The local state directory is fixed before anything else is resolved, so
    // the identity prompts and the SSH selection below cannot move where the
    // generated key lands.
    let home = KeyGenerationHome::fix(context.local_state()?)?;
    let member_handle =
        resolve_required_cli_member_handle(&context, args.member.member_handle.clone(), true)?;
    let github_user =
        resolve_cli_key_generation_github_user(true, args.github_user.clone(), &context)?;
    eprintln!();
    let ssh_ctx = resolve_ssh_context(&context)?;
    let result = generate_key_command(
        home,
        member_handle,
        github_user,
        KeyExpiryRequest {
            expires_at: &args.expires_at,
            valid_for: &args.valid_for,
        },
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
