// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External process execution helpers.

use crate::support::secret::SecretEnvMap;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::Command;

pub(crate) const STANDARD_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TERM",
    "TMPDIR",
    "TMP",
    "TEMP",
    "TZ",
    "SHELL",
    "USER",
    "LOGNAME",
];

/// Execute a command with environment variables and return its exit code.
pub fn execute_command_with_env(
    cmd: &str,
    cmd_args: &[String],
    env_vars: &SecretEnvMap,
) -> Result<i32> {
    let mut command = Command::new(cmd);
    command.args(cmd_args);
    configure_child_env_secret(&mut command, env_vars);

    let status = command.status().map_err(|e| {
        Error::io_with_source(format!("Failed to execute command '{}': {}", cmd, e), e)
    })?;

    Ok(status.code().unwrap_or(1))
}

pub(crate) fn configure_child_env_secret(command: &mut Command, env_vars: &SecretEnvMap) {
    command.env_clear();
    command.envs(load_standard_env_vars());
    for (key, value) in env_vars {
        command.env(key, value.as_str());
    }
}

pub(crate) fn configure_child_env_os(command: &mut Command, env_vars: &BTreeMap<String, OsString>) {
    command.env_clear();
    command.envs(build_child_env_map(env_vars));
}

pub(crate) fn build_child_env_map(
    env_vars: &BTreeMap<String, OsString>,
) -> BTreeMap<String, OsString> {
    let mut merged = load_standard_env_vars();
    merged.extend(
        env_vars
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    merged
}

fn load_standard_env_vars() -> BTreeMap<String, OsString> {
    STANDARD_ENV_KEYS
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| ((*key).to_string(), value)))
        .collect()
}
