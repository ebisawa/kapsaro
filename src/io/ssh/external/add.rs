// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Default implementation of the `SshAdd` trait using the system ssh-add command.

use super::build_ssh_child_env;
use super::traits::SshAdd;
use crate::io::process::set_child_env_os;
use crate::io::ssh::agent::socket::resolve_agent_socket_path;
use crate::io::ssh::SshError;
use crate::{Error, Result};
use std::process::Command;

/// Default implementation of `SshAdd` that invokes the system `ssh-add` binary.
pub struct DefaultSshAdd {
    ssh_add_path: String,
}

impl DefaultSshAdd {
    /// Create a new `DefaultSshAdd` using the given binary path.
    pub fn new(ssh_add_path: impl Into<String>) -> Self {
        Self {
            ssh_add_path: ssh_add_path.into(),
        }
    }
}

impl SshAdd for DefaultSshAdd {
    fn list_keys(&self) -> Result<String> {
        let socket_path = resolve_agent_socket_path()?;
        let mut command = Command::new(&self.ssh_add_path);
        set_child_env_os(
            &mut command,
            &build_ssh_child_env(Some(socket_path.as_path())),
        );

        let output = command.arg("-L").output().map_err(|e| {
            Error::from(SshError::build_operation_failed_error_with_source(
                format!("Failed to run ssh-add -L: {}", e),
                e,
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SshError::build_operation_failed_error(format!(
                "ssh-add -L failed: {}",
                stderr
            ))
            .into());
        }

        String::from_utf8(output.stdout).map_err(|e| {
            Error::from(SshError::build_operation_failed_error_with_source(
                format!("Invalid UTF-8 in ssh-add output: {}", e),
                e,
            ))
        })
    }
}
