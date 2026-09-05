// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Default implementation of the `SshAdd` trait using the system ssh-add command.

use super::runner;
use super::runner::SshCommandRunner;
use super::traits::SshAdd;
use crate::io::ssh::SshError;
use crate::Result;
use std::path::PathBuf;
use std::process::Output;

/// Default implementation of `SshAdd` that invokes the system `ssh-add` binary.
pub struct DefaultSshAdd {
    ssh_add_path: String,
    agent_socket: Option<PathBuf>,
}

impl DefaultSshAdd {
    /// Bind ssh-add to its binary and caller-selected agent socket.
    pub fn new(ssh_add_path: impl Into<String>, agent_socket: Option<PathBuf>) -> Self {
        Self {
            ssh_add_path: ssh_add_path.into(),
            agent_socket,
        }
    }
}

impl SshAdd for DefaultSshAdd {
    fn list_keys(&self) -> Result<String> {
        let output =
            SshCommandRunner::required_agent(self.ssh_add_path.clone(), self.agent_socket.clone())
                .output(["-L"], |e| {
                    SshError::build_operation_failed_error_with_source(
                        format!("Failed to run ssh-add -L: {}", e),
                        e,
                    )
                })?;

        parse_list_keys_output(output)
    }
}

/// Map an `ssh-add -L` result to the agent key listing, or to the user-facing error.
fn parse_list_keys_output(output: Output) -> Result<String> {
    if !output.status.success() {
        let stderr = runner::decode_lossy(&output.stderr);
        return Err(SshError::build_operation_failed_error(format!(
            "ssh-add -L failed: {}",
            stderr
        ))
        .into());
    }

    runner::decode_stdout_utf8(output, |e| {
        format!("Invalid UTF-8 in ssh-add output: {}", e)
    })
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_ssh_external_add_test.rs"]
mod io_ssh_external_add_test;
