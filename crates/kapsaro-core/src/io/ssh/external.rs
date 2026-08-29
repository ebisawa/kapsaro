// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External SSH tool adapters (ssh-keygen, ssh-add)

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

pub mod add;
pub mod keygen;
pub mod pubkey;
pub(crate) mod runner;
pub mod traits;

const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";

pub(super) fn build_ssh_child_env(agent_socket: Option<&Path>) -> BTreeMap<String, OsString> {
    let mut extra_env = BTreeMap::new();
    if let Some(path) = agent_socket {
        extra_env.insert(SSH_AUTH_SOCK.to_string(), path.as_os_str().to_os_string());
    }
    extra_env
}

/// Keep an inherited agent socket away from a child that does not need one.
///
/// Leaving the variable out of the child environment is not enough: the child
/// inherits this process's own value, and `ssh-keygen -Y sign` opens the agent
/// whenever the variable is set, even when the key file alone can sign.
pub(super) fn remove_ssh_agent_socket_from_child(command: &mut Command) {
    command.env_remove(SSH_AUTH_SOCK);
}
