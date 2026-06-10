// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Default implementation of the `SshAdd` trait using the system ssh-add command.

use super::runner;
use super::runner::SshCommandRunner;
use super::traits::SshAdd;
use crate::io::ssh::SshError;
use crate::Result;

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
        let output =
            SshCommandRunner::required_agent(self.ssh_add_path.clone()).output(["-L"], |e| {
                SshError::build_operation_failed_error_with_source(
                    format!("Failed to run ssh-add -L: {}", e),
                    e,
                )
            })?;

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
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/ssh_external_env_test.rs"]
mod ssh_external_env_test;
