// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Guards for commands that are unavailable in environment-variable key mode.

use kapsaro_core::cli_api::app::context::env_key::is_env_key_mode;
use kapsaro_core::cli_api::app::trust::CommandCapability;
use kapsaro_core::Result;
use tracing::debug;

pub(crate) fn ensure_env_mode_command_allowed(capability: CommandCapability) -> Result<()> {
    if !is_env_key_mode() {
        debug!("[CLI] env-key mode inactive");
        return Ok(());
    }

    if capability.allows_env_key_mode() {
        debug!("[CLI] env-key mode allowed for {}", capability.label());
        return Ok(());
    }

    debug!("[CLI] env-key mode rejected for {}", capability.label());
    Err(kapsaro_core::Error::build_invalid_operation_error(format!(
        "Command unavailable in environment-variable key mode.\n\
             Command: {}\n\
             Supported commands: run, decrypt, get, list, doctor.",
        capability.label()
    )))
}
