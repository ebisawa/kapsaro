// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Guards for commands that are unavailable in environment-variable key mode.

use secretenv_core::cli_api::app::context::env_key::is_env_key_mode;
use secretenv_core::cli_api::app::trust::CommandCapability;
use secretenv_core::Result;
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
    Err(secretenv_core::Error::build_invalid_operation_error(
        format!(
            "'{}' is unavailable in environment-variable key mode; env mode only supports \
         these commands: run, decrypt, get, list, doctor.",
            capability.label()
        ),
    ))
}
