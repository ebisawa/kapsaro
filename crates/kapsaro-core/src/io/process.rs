// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Child-process environment isolation helpers.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::process::Command;

pub(crate) fn set_child_env_os(command: &mut Command, env_vars: &BTreeMap<String, OsString>) {
    remove_parent_kapsaro_env_vars(command);
    command.envs(env_vars);
}

/// Drop every `KAPSARO_*` variable inherited from the parent so child processes
/// never observe this process's own configuration or key material.
pub fn remove_parent_kapsaro_env_vars(command: &mut Command) {
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
