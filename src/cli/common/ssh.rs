// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared SSH signing context resolution for CLI commands.

use crate::cli::identity_prompt::select_ssh_key;
use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;
use kapsaro_core::cli_api::app::context::ssh::{
    build_ssh_signing_context, resolve_ssh_key_candidates, SshSigningContextResolution,
};
use kapsaro_core::Result;

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
