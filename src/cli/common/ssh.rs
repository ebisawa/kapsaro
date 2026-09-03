// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared SSH signing context resolution for CLI commands.

use crate::cli::common::context::CliContext;
use crate::cli::identity_prompt::select_ssh_key;
use kapsaro_core::api::ssh::{
    build_ssh_signing_context, resolve_ssh_key_candidates, SshSigningContextResolution,
};
use kapsaro_core::Result;

/// Run the 3-phase SSH signing context resolution for key generation.
/// Phase 1: Discover key candidates from explicit CLI-resolved inputs
/// Phase 2: Select key (auto for 1, interactive for multiple, error for 0)
/// Phase 3: Build signing context with determinism check
pub(crate) fn resolve_ssh_context(context: &CliContext) -> Result<SshSigningContextResolution> {
    let inputs = context.ssh_signing_inputs()?;
    let candidates = resolve_ssh_key_candidates(&inputs)?;
    let selected = select_ssh_key(&candidates)?;
    build_ssh_signing_context(&inputs, &candidates[selected].public_key, true)
}
