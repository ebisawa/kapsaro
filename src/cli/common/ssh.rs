// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared SSH signing context resolution for CLI commands.

use crate::cli::identity_prompt::select_ssh_key;
use kapsaro_core::cli_api::app::context::env_key::is_env_key_mode;
use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;
use kapsaro_core::cli_api::app::context::ssh::{
    build_ssh_signing_context, resolve_ssh_context_by_active_key, resolve_ssh_key_candidates,
    SshSigningContextResolution,
};
use kapsaro_core::Result;
use tracing::debug;

/// Run the 3-phase SSH signing context resolution for key generation.
/// Phase 1: Discover key candidates (via app layer)
/// Phase 2: Select key (auto for 1, interactive for multiple, error for 0)
/// Phase 3: Build signing context with determinism check (via app layer)
pub(crate) fn resolve_ssh_context(
    options: &CommonCommandOptions,
) -> Result<SshSigningContextResolution> {
    let candidates = resolve_ssh_key_candidates(options)?;
    let selected = select_ssh_key(&candidates)?;
    build_ssh_signing_context(options, &candidates[selected].public_key, true)
}

/// Resolve SSH context using the active key's fingerprint.
/// No interactive selection; auto-matches against ssh-agent candidates.
pub(crate) fn resolve_ssh_context_for_active_key(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<SshSigningContextResolution> {
    let ctx = resolve_ssh_context_by_active_key(options, member_handle)?;
    debug!("[SSH] Using SSH key: {}", ctx.fingerprint);
    Ok(ctx)
}

/// Resolve SSH context if needed, skipping in env-var key mode.
///
/// Returns `None` when `KAPSARO_PRIVATE_KEY` is set (CI mode),
/// causing the app layer to use environment variable key loading.
pub(crate) fn resolve_ssh_context_optional(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<Option<SshSigningContextResolution>> {
    if is_env_key_mode() {
        debug!("[SSH] Environment variable key mode active, skipping SSH resolution");
        Ok(None)
    } else {
        Ok(Some(resolve_ssh_context_for_active_key(
            options,
            member_handle,
        )?))
    }
}
