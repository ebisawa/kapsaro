// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared runner for external SSH commands.

use super::build_ssh_child_env;
use crate::io::process::set_child_env_os;
use crate::io::ssh::agent::socket::resolve_agent_socket_path;
use crate::io::ssh::SshError;
use crate::{Error, Result};
use std::ffi::OsStr;
use std::io;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::string::FromUtf8Error;

#[derive(Debug, Clone, Copy)]
pub(super) enum AgentSocketPolicy {
    Optional,
    Required,
}

pub(super) struct SshCommandRunner {
    program: String,
    agent_socket_policy: AgentSocketPolicy,
}

impl SshCommandRunner {
    pub(super) fn optional_agent(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            agent_socket_policy: AgentSocketPolicy::Optional,
        }
    }

    pub(super) fn required_agent(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            agent_socket_policy: AgentSocketPolicy::Required,
        }
    }

    pub(super) fn output<I, S>(
        &self,
        args: I,
        build_spawn_error: impl FnOnce(io::Error) -> SshError,
    ) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command()?
            .args(args)
            .output()
            .map_err(|e| Error::from(build_spawn_error(e)))
    }

    pub(super) fn output_with_stdin<I, S>(
        &self,
        args: I,
        stdin: &[u8],
        build_spawn_error: impl FnOnce(io::Error) -> SshError,
        wait_error_context: &'static str,
    ) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = self
            .command()?
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::from(build_spawn_error(e)))?;

        if let Some(mut child_stdin) = child.stdin.take() {
            child_stdin.write_all(stdin).map_err(|e| {
                Error::from(SshError::build_operation_failed_error_with_source(
                    "Failed to write to stdin",
                    e,
                ))
            })?;
        }

        child.wait_with_output().map_err(|e| {
            Error::from(SshError::build_operation_failed_error_with_source(
                wait_error_context,
                e,
            ))
        })
    }

    fn command(&self) -> Result<Command> {
        let mut command = Command::new(&self.program);
        let agent_socket = self.agent_socket()?;
        set_child_env_os(&mut command, &build_ssh_child_env(agent_socket.as_deref()));
        Ok(command)
    }

    fn agent_socket(&self) -> Result<Option<std::path::PathBuf>> {
        match self.agent_socket_policy {
            AgentSocketPolicy::Optional => Ok(resolve_agent_socket_path().ok()),
            AgentSocketPolicy::Required => resolve_agent_socket_path().map(Some),
        }
    }
}

pub(super) fn decode_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

pub(super) fn decode_stdout_utf8(
    output: Output,
    build_context: impl FnOnce(&FromUtf8Error) -> String,
) -> Result<String> {
    String::from_utf8(output.stdout).map_err(|e| {
        let context = build_context(&e);
        Error::from(SshError::build_operation_failed_error_with_source(
            context, e,
        ))
    })
}

pub(super) fn failure_details(output: &Output) -> String {
    if !output.stderr.is_empty() {
        decode_lossy(&output.stderr)
    } else if !output.stdout.is_empty() {
        decode_lossy(&output.stdout)
    } else {
        format!("exit code: {:?}", output.status.code())
    }
}
