// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External process execution helpers.

use crate::support::secret::SecretEnvironmentMap;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::process::Command;
use tracing::debug;

/// Execute a command with environment variables and return its exit code.
pub fn execute_command_with_env(
    cmd: &str,
    cmd_args: &[String],
    env_vars: &SecretEnvironmentMap,
) -> Result<i32> {
    debug!(
        "[IO] child process: command={}, secret_environment_count={}",
        cmd,
        env_vars.len()
    );
    let mut command = Command::new(cmd);
    command.args(cmd_args);
    set_child_env_secret(&mut command, env_vars);

    let status = command.status().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to execute command '{}': {}", cmd, e), e)
    })?;

    let code = status.code().unwrap_or(1);
    debug!("[IO] child process exited: command={}, code={}", cmd, code);
    Ok(code)
}

pub(crate) fn set_child_env_secret(command: &mut Command, env_vars: &SecretEnvironmentMap) {
    remove_parent_kapsaro_env_vars(command);
    for (key, value) in env_vars {
        command.env(key, value.as_str());
    }
}

pub(crate) fn set_child_env_os(command: &mut Command, env_vars: &BTreeMap<String, OsString>) {
    remove_parent_kapsaro_env_vars(command);
    command.envs(env_vars);
}

fn remove_parent_kapsaro_env_vars(command: &mut Command) {
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_kapsaro_env_key(key))
    {
        command.env_remove(key);
    }
}

fn is_kapsaro_env_key(key: &OsStr) -> bool {
    key.to_str().is_some_and(|key| key.starts_with("KAPSARO_"))
}

#[cfg(test)]
#[path = "../../tests/unit/internal/io_process_env_test.rs"]
mod io_process_env_test;
