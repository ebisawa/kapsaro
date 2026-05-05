// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Default implementation of the `SshKeygen` trait using the system ssh-keygen command.

use super::traits::SshKeygen;
use super::{runner, temp_file};
use crate::io::ssh::external::runner::SshCommandRunner;
use crate::io::ssh::protocol::sshsig::parse_sshsig_armored;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::SshError;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::ffi::OsString;
use std::path::Path;
use std::process::Output;
use zeroize::Zeroizing;

/// Default implementation of `SshKeygen` that invokes the system `ssh-keygen` binary.
pub struct DefaultSshKeygen {
    ssh_keygen_path: String,
}

impl DefaultSshKeygen {
    /// Create a new `DefaultSshKeygen` using the given binary path.
    pub fn new(ssh_keygen_path: impl Into<String>) -> Self {
        Self {
            ssh_keygen_path: ssh_keygen_path.into(),
        }
    }
}

impl SshKeygen for DefaultSshKeygen {
    fn derive_public_key(&self, key_path: &Path) -> Result<String> {
        let args = vec![
            OsString::from("-y"),
            OsString::from("-f"),
            key_path.as_os_str().to_os_string(),
        ];
        let output =
            SshCommandRunner::optional_agent(self.ssh_keygen_path.clone()).output(args, |e| {
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
        key_path: &Path,
        namespace: &str,
        ssh_pubkey: &str,
        data: &[u8],
    ) -> Result<Ed25519RawSignature> {
        let is_public_key = key_path
            .extension()
            .map(|ext| ext == "pub")
            .unwrap_or(false);

        let key_path_str = key_path.to_str().ok_or_else(|| {
            Error::from(SshError::build_operation_failed_error(format!(
                "SSH key path contains invalid UTF-8: {}",
                format_path_relative_to_cwd(key_path)
            )))
        })?;

        let output = execute_sign_command(&self.ssh_keygen_path, key_path_str, namespace, data)?;
        check_sign_output(&output, is_public_key)?;
        parse_sign_stdout(output.stdout, namespace, ssh_pubkey)
    }

    fn verify(
        &self,
        ssh_pubkey: &str,
        namespace: &str,
        message: &[u8],
        signature: &str,
    ) -> Result<()> {
        let allowed = format!(
            "{} namespaces=\"{}\" {}\n",
            namespace, namespace, ssh_pubkey
        );
        let allowed_file = temp_file::save_temp_str(&allowed)?;
        let sig_file = temp_file::save_temp_str(signature)?;

        let args = vec![
            OsString::from("-Y"),
            OsString::from("verify"),
            OsString::from("-f"),
            allowed_file.path().as_os_str().to_os_string(),
            OsString::from("-I"),
            OsString::from(namespace),
            OsString::from("-n"),
            OsString::from(namespace),
            OsString::from("-s"),
            sig_file.path().as_os_str().to_os_string(),
        ];
        let output = SshCommandRunner::optional_agent(self.ssh_keygen_path.clone())
            .output_with_stdin(
                args,
                message,
                |e| {
                    SshError::build_operation_failed_error_with_source(
                        "Failed to spawn ssh-keygen",
                        e,
                    )
                },
                "Failed to wait for ssh-keygen",
            )?;

        check_verify_output(output)
    }
}

fn execute_sign_command(
    ssh_keygen_path: &str,
    key_path_str: &str,
    namespace: &str,
    data: &[u8],
) -> Result<std::process::Output> {
    let args = [
        "-Y",
        "sign",
        "-f",
        key_path_str,
        "-n",
        namespace,
        "-O",
        "hashalg=sha256",
    ];
    SshCommandRunner::optional_agent(ssh_keygen_path.to_string()).output_with_stdin(
        args,
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

fn check_sign_output(output: &Output, is_public_key: bool) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = runner::decode_lossy(&output.stderr);
    let hint = if is_public_key {
        "When using a public key file, the corresponding private key must be loaded in ssh-agent.\n\
        Check: ssh-add -l\n\
        Or use the private key file (without .pub extension) instead."
    } else {
        "Ensure the private key file is accessible and has correct permissions.\n\
        Or load the key in ssh-agent: ssh-add <key-file>"
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

fn check_verify_output(output: Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let details = runner::failure_details(&output);
    Err(SshError::build_operation_failed_error(format!(
        "ssh-keygen -Y verify failed: {}",
        details.trim()
    ))
    .into())
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/ssh_external_keygen_helpers_test.rs"]
mod tests;
