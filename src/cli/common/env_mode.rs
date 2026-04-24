// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Guards for commands that are unavailable in environment-variable key mode.

use crate::app::context::env_key::is_env_key_mode;
use crate::app::trust::CommandCapability;
use crate::Result;

pub(crate) fn ensure_env_mode_command_allowed(capability: CommandCapability) -> Result<()> {
    if !is_env_key_mode() {
        return Ok(());
    }

    if capability.allows_env_key_mode() {
        return Ok(());
    }

    Err(crate::Error::build_invalid_operation_error(format!(
        "'{}' is unavailable in environment-variable key mode; env mode only supports \
         these commands: run, decrypt, get, list.",
        capability.label()
    )))
}
