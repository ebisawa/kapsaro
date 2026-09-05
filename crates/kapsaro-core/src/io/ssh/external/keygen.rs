// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Default implementation of the `SshKeygen` trait using the system ssh-keygen command.

use super::runner;
use super::traits::SshKeygen;
use crate::io::ssh::external::runner::SshCommandRunner;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use crate::io::ssh::protocol::sshsig::parse_sshsig_armored;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::SshError;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Output;
use zeroize::Zeroizing;

/// Default implementation of `SshKeygen` that invokes the system `ssh-keygen` binary.
pub struct DefaultSshKeygen {
    ssh_keygen_path: String,
    agent_socket: Option<PathBuf>,
}

impl DefaultSshKeygen {
    /// Bind ssh-keygen to its binary and optional caller-selected agent socket.
    pub fn new(ssh_keygen_path: impl Into<String>, agent_socket: Option<PathBuf>) -> Self {
        Self {
            ssh_keygen_path: ssh_keygen_path.into(),
            agent_socket,
        }
    }
}

/// `ssh-keygen -y -f <key>` prints the public half of a private key file.
fn build_derive_public_key_args(key_path: &Path) -> Vec<OsString> {
    vec![
        OsString::from("-y"),
        OsString::from("-f"),
        key_path.as_os_str().to_os_string(),
    ]
}

/// `ssh-keygen -Y sign` takes the message on stdin and writes the armored
/// signature to stdout, so the signature never reaches a file on disk.
fn build_sign_args<'a>(key_path: &'a str, namespace: &'a str) -> [&'a str; 8] {
    [
        "-Y",
        "sign",
        "-f",
        key_path,
        "-n",
        namespace,
        "-O",
        "hashalg=sha256",
    ]
}

impl SshKeygen for DefaultSshKeygen {
    fn derive_public_key(&self, key_path: &Path) -> Result<String> {
        let args = build_derive_public_key_args(key_path);
        // `-y -f` reads the private key file itself and never asks the agent.
        let output =
            SshCommandRunner::without_agent(self.ssh_keygen_path.clone()).output(args, |e| {
                SshError::build_operation_failed_error_with_source(
                    "Failed to execute ssh-keygen",
                    e,
                )
            })?;

        if !output.status.success() {
            let stderr = runner::decode_lossy(&output.stderr);
            return Err(SshError::build_operation_failed_error(format!(
                "ssh-keygen -y -f failed: {}",
                stderr
            ))
            .into());
        }

        runner::decode_stdout_utf8(output, |_| "Invalid UTF-8 in ssh-keygen output".to_string())
            .map(|s| s.trim().to_string())
    }

    fn sign(
        &self,
        key: &SshKeyDescriptor,
        namespace: &str,
        ssh_pubkey: &str,
        data: &[u8],
    ) -> Result<Ed25519RawSignature> {
        let is_public_key = key.is_public_key_file();
        let key_path = key.as_path();

        let key_path_str = key_path.to_str().ok_or_else(|| {
            Error::from(SshError::build_operation_failed_error(format!(
                "SSH key path contains invalid UTF-8: {}",
                format_path_relative_to_cwd(key_path)
            )))
        })?;

        let output = execute_sign_command(
            &self.ssh_keygen_path,
            key_path_str,
            namespace,
            data,
            is_public_key,
            self.agent_socket.clone(),
        )?;
        enforce_sign_output_success(&output, is_public_key)?;
        parse_sign_stdout(output.stdout, namespace, ssh_pubkey)
    }
}

/// Run `ssh-keygen -Y sign`, handing it the agent only when it needs one.
///
/// A public key carries no secret, so signing with it means asking the agent
/// for the private half. A private key file signs on its own, and `ssh-keygen`
/// still opens the agent whenever `SSH_AUTH_SOCK` is set, so the socket is kept
/// away from the child in that case.
fn execute_sign_command(
    ssh_keygen_path: &str,
    key_path_str: &str,
    namespace: &str,
    data: &[u8],
    is_public_key: bool,
    agent_socket: Option<PathBuf>,
) -> Result<std::process::Output> {
    let runner = if is_public_key {
        SshCommandRunner::optional_agent(ssh_keygen_path.to_string(), agent_socket)
    } else {
        SshCommandRunner::without_agent(ssh_keygen_path.to_string())
    };
    runner.output_with_stdin(
        build_sign_args(key_path_str, namespace),
        data,
        |e| {
            SshError::build_operation_failed_error_with_source(
                format!(
                    "ssh-keygen command failed: {}\n\
                    Diagnostic: Ensure '{}' supports '-Y sign' (OpenSSH 8.0+).",
                    e, ssh_keygen_path
                ),
                e,
            )
        },
        "Failed to wait for ssh-keygen",
    )
}

fn enforce_sign_output_success(output: &Output, is_public_key: bool) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = runner::decode_lossy(&output.stderr);
    let hint = if is_public_key {
        "When using a public key file, the corresponding private key must be loaded in ssh-agent.\n\
        Check: ssh-add -l\n\
        Or use the private key file (without .pub extension) instead."
    } else {
        // Signing from a private key file runs without the agent, so loading
        // the key into one changes nothing here.
        "Check that the private key file is readable, and enter its passphrase when the key is \
        protected by one.\n\
        Or pass the matching .pub file to sign through ssh-agent instead."
    };
    Err(SshError::build_operation_failed_error(format!(
        "ssh-keygen -Y sign failed: {}\nHint: {}",
        stderr, hint
    ))
    .into())
}

fn parse_sign_stdout(
    stdout: Vec<u8>,
    expected_namespace: &str,
    expected_ssh_pubkey: &str,
) -> Result<Ed25519RawSignature> {
    let stdout = Zeroizing::new(stdout);
    if stdout.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(SshError::build_operation_failed_error(
            "ssh-keygen -Y sign produced empty signature output",
        )
        .into());
    }

    let armored = std::str::from_utf8(stdout.as_slice()).map_err(|e| {
        Error::from(SshError::build_operation_failed_error_with_source(
            "Invalid UTF-8 in ssh-keygen output",
            e,
        ))
    })?;
    let blob = parse_sshsig_armored(armored, expected_namespace, expected_ssh_pubkey)?;
    blob.extract_ed25519_raw()
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_ssh_external_keygen_helpers_test.rs"]
mod io_ssh_external_keygen_helpers_test;
