// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External process execution helpers.

use crate::support::secret::SecretEnvMap;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::process::Command;

/// Execute a command with environment variables and return its exit code.
pub fn execute_command_with_env(
    cmd: &str,
    cmd_args: &[String],
    env_vars: &SecretEnvMap,
) -> Result<i32> {
    let mut command = Command::new(cmd);
    command.args(cmd_args);
    set_child_env_secret(&mut command, env_vars);

    let status = command.status().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to execute command '{}': {}", cmd, e), e)
    })?;

    Ok(status.code().unwrap_or(1))
}

pub(crate) fn set_child_env_secret(command: &mut Command, env_vars: &SecretEnvMap) {
    remove_parent_secretenv_env_vars(command);
    for (key, value) in env_vars {
        command.env(key, value.as_str());
    }
}

pub(crate) fn set_child_env_os(command: &mut Command, env_vars: &BTreeMap<String, OsString>) {
    remove_parent_secretenv_env_vars(command);
    command.envs(env_vars);
}

fn remove_parent_secretenv_env_vars(command: &mut Command) {
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_secretenv_env_key(key))
    {
        command.env_remove(key);
    }
}

fn is_secretenv_env_key(key: &OsStr) -> bool {
    key.to_str()
        .is_some_and(|key| key.starts_with("SECRETENV_"))
}
