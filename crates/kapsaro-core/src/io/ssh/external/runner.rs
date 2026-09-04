// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared runner for external SSH commands.

use super::{build_ssh_child_env, remove_ssh_agent_socket_from_child};
use crate::io::process::set_child_env_os;
use crate::io::ssh::SshError;
use crate::{Error, Result};
use std::ffi::OsStr;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::string::FromUtf8Error;

#[derive(Debug, Clone)]
pub(super) enum AgentSocketPolicy {
    Disabled,
    Optional(Option<PathBuf>),
    Required(Option<PathBuf>),
}

pub(super) struct SshCommandRunner {
    program: String,
    agent_socket_policy: AgentSocketPolicy,
}

impl SshCommandRunner {
    /// Runner for a command that signs or reads with a key file alone.
    ///
    /// The agent socket is neither resolved nor inherited, so the operator's
    /// agent is left untouched by work it has no part in.
    pub(super) fn without_agent(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            agent_socket_policy: AgentSocketPolicy::Disabled,
        }
    }

    pub(super) fn optional_agent(
        program: impl Into<String>,
        agent_socket: Option<PathBuf>,
    ) -> Self {
        Self {
            program: program.into(),
            agent_socket_policy: AgentSocketPolicy::Optional(agent_socket),
        }
    }

    pub(super) fn required_agent(
        program: impl Into<String>,
        agent_socket: Option<PathBuf>,
    ) -> Self {
        Self {
            program: program.into(),
            agent_socket_policy: AgentSocketPolicy::Required(agent_socket),
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
            if let Err(error) = child_stdin.write_all(stdin) {
                drop(child_stdin);
                return Err(self.build_stdin_write_error(child, error, wait_error_context));
            }
        }

        child.wait_with_output().map_err(|e| {
            Error::from(SshError::build_operation_failed_error_with_source(
                wait_error_context,
                e,
            ))
        })
    }

    /// Report a failed stdin write with what the child said before it stopped.
    ///
    /// The write fails because the child is no longer reading, which it is
    /// entitled to do only by having stopped: the account it left on stderr,
    /// and the status it exited with, are the only description of why. Reaping
    /// it here also keeps a child that already failed from being left behind.
    fn build_stdin_write_error(
        &self,
        child: std::process::Child,
        write_error: io::Error,
        wait_error_context: &'static str,
    ) -> Error {
        let output = match child.wait_with_output() {
            Ok(output) => output,
            Err(wait_error) => {
                return Error::from(SshError::build_operation_failed_error_with_source(
                    format!(
                        "Failed to write to stdin of {} ({write_error}), and \
                         {wait_error_context}",
                        self.program
                    ),
                    wait_error,
                ))
            }
        };
        Error::from(SshError::build_operation_failed_error_with_source(
            format!(
                "Failed to write to stdin: {} exited with {}: {}",
                self.program,
                output.status,
                decode_lossy(&output.stderr).trim()
            ),
            write_error,
        ))
    }

    /// Build the child command with the agent socket this policy allows.
    ///
    /// The policy is read once: a disabled agent both contributes no socket and
    /// strips the inherited one, so deciding twice could leave the two halves
    /// disagreeing and let the operator's agent through.
    fn command(&self) -> Result<Command> {
        let mut command = Command::new(&self.program);
        match &self.agent_socket_policy {
            AgentSocketPolicy::Disabled => {
                set_child_env_os(&mut command, &build_ssh_child_env(None));
                remove_ssh_agent_socket_from_child(&mut command);
            }
            AgentSocketPolicy::Optional(agent_socket) => {
                set_child_env_os(&mut command, &build_ssh_child_env(agent_socket.as_deref()));
                if agent_socket.is_none() {
                    remove_ssh_agent_socket_from_child(&mut command);
                }
            }
            AgentSocketPolicy::Required(Some(agent_socket)) => {
                set_child_env_os(&mut command, &build_ssh_child_env(Some(agent_socket)));
            }
            AgentSocketPolicy::Required(None) => return Err(build_missing_agent_socket_error()),
        }
        Ok(command)
    }
}

fn build_missing_agent_socket_error() -> Error {
    SshError::build_operation_failed_error(
        "SSH agent socket was not resolved before starting the operation",
    )
    .into()
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

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_ssh_external_runner_test.rs"]
mod io_ssh_external_runner_test;
