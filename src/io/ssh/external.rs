// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External SSH tool adapters (ssh-keygen, ssh-add)

use crate::io::process::build_restricted_child_env_map;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

pub mod add;
pub mod keygen;
pub mod pubkey;
pub mod temp_file;
pub mod traits;

pub(crate) fn build_ssh_child_env(agent_socket: Option<&Path>) -> BTreeMap<String, OsString> {
    let mut extra_env = BTreeMap::new();
    if let Some(path) = agent_socket {
        extra_env.insert("SSH_AUTH_SOCK".to_string(), path.as_os_str().to_os_string());
    }
    build_restricted_child_env_map(&extra_env)
}
