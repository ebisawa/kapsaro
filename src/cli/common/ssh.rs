// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared SSH signing context resolution for CLI commands.

use crate::app::context::env_key::is_env_key_mode;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::{
    build_ssh_signing_context, resolve_ssh_context_by_active_key, resolve_ssh_key_candidates,
    ResolvedSshSigner,
};
use crate::cli::identity_prompt::select_ssh_key;
use crate::Result;
use tracing::debug;

/// Run the 3-phase SSH signing context resolution for key generation.
/// Phase 1: Discover key candidates (via app layer)
/// Phase 2: Select key (auto for 1, interactive for multiple, error for 0)
/// Phase 3: Build signing context with determinism check (via app layer)
pub(crate) fn resolve_ssh_context(options: &CommonCommandOptions) -> Result<ResolvedSshSigner> {
    let candidates = resolve_ssh_key_candidates(options)?;
    let selected = select_ssh_key(&candidates)?;
    build_ssh_signing_context(options, &candidates[selected].public_key, true)
}

/// Resolve SSH context using the active key's fingerprint.
/// No interactive selection; auto-matches against ssh-agent candidates.
pub(crate) fn resolve_ssh_context_for_active_key(
    options: &CommonCommandOptions,
    member_id: Option<String>,
) -> Result<ResolvedSshSigner> {
    let ctx = resolve_ssh_context_by_active_key(options, member_id)?;
    debug!("[SSH] Using SSH key: {}", ctx.fingerprint);
    Ok(ctx)
}

/// Resolve SSH context if needed, skipping in env-var key mode.
///
/// Returns `None` when `SECRETENV_PRIVATE_KEY` is set (CI mode),
/// causing the app layer to use environment variable key loading.
pub(crate) fn resolve_ssh_context_optional(
    options: &CommonCommandOptions,
    member_id: Option<String>,
) -> Result<Option<ResolvedSshSigner>> {
    if is_env_key_mode() {
        debug!("[SSH] Environment variable key mode active, skipping SSH resolution");
        Ok(None)
    } else {
        Ok(Some(resolve_ssh_context_for_active_key(
            options, member_id,
        )?))
    }
}
