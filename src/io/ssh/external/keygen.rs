// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Default implementation of the `SshKeygen` trait using the system ssh-keygen command.

use super::traits::SshKeygen;
use super::{build_ssh_child_env, temp_file};
use crate::io::process::set_child_env_os;
use crate::io::ssh::agent::socket::resolve_agent_socket_path;
use crate::io::ssh::protocol::sshsig::parse_sshsig_armored;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::SshError;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
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
        let mut command = Command::new(&self.ssh_keygen_path);
        set_child_env_os(
            &mut command,
            &build_ssh_child_env(resolve_agent_socket_path().ok().as_deref()),
        );

        let output = command
            .args(["-y", "-f"])
            .arg(key_path)
            .output()
            .map_err(|e| {
                Error::from(SshError::build_operation_failed_error_with_source(
                    "Failed to execute ssh-keygen",
                    e,
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SshError::build_operation_failed_error(format!(
                "ssh-keygen -y -f failed: {}",
                stderr
            ))
            .into());
        }

        String::from_utf8(output.stdout)
            .map(|s| s.trim().to_string())
            .map_err(|e| {
                Error::from(SshError::build_operation_failed_error_with_source(
                    "Invalid UTF-8 in ssh-keygen output",
                    e,
                ))
            })
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

        let mut child = Command::new(&self.ssh_keygen_path);
        set_child_env_os(
            &mut child,
            &build_ssh_child_env(resolve_agent_socket_path().ok().as_deref()),
        );

        let mut child = child
            .args(["-Y", "verify", "-f"])
            .arg(allowed_file.path())
            .args(["-I", namespace, "-n", namespace, "-s"])
            .arg(sig_file.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                Error::from(SshError::build_operation_failed_error_with_source(
                    "Failed to spawn ssh-keygen",
                    e,
                ))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(message).map_err(|e| {
                Error::from(SshError::build_operation_failed_error_with_source(
                    "Failed to write to stdin",
                    e,
                ))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            Error::from(SshError::build_operation_failed_error_with_source(
                "Failed to wait for ssh-keygen",
                e,
            ))
        })?;

        check_verify_output(output)
    }
}

fn execute_sign_command(
    ssh_keygen_path: &str,
    key_path_str: &str,
    namespace: &str,
    data: &[u8],
) -> Result<std::process::Output> {
    let mut child = Command::new(ssh_keygen_path);
    set_child_env_os(
        &mut child,
        &build_ssh_child_env(resolve_agent_socket_path().ok().as_deref()),
    );

    let mut child = child
        .args(["-Y", "sign"])
        .args(["-f", key_path_str])
        .args(["-n", namespace])
        .args(["-O", "hashalg=sha256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            Error::from(SshError::build_operation_failed_error_with_source(
                format!(
                    "ssh-keygen command failed: {}\n\
                    Diagnostic: Ensure '{}' supports '-Y sign' (OpenSSH 8.0+).",
                    e, ssh_keygen_path
                ),
                e,
            ))
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data).map_err(|e| {
            Error::from(SshError::build_operation_failed_error_with_source(
                "Failed to write to stdin",
                e,
            ))
        })?;
    }

    child.wait_with_output().map_err(|e| {
        Error::from(SshError::build_operation_failed_error_with_source(
            "Failed to wait for ssh-keygen",
            e,
        ))
    })
}

fn check_sign_output(output: &std::process::Output, is_public_key: bool) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
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

fn check_verify_output(output: std::process::Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let details = if !output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else if !output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stdout).to_string()
    } else {
        format!("exit code: {:?}", output.status.code())
    };
    Err(SshError::build_operation_failed_error(format!(
        "ssh-keygen -Y verify failed: {}",
        details.trim()
    ))
    .into())
}

#[cfg(test)]
#[path = "../../../../tests/unit/ssh_external_keygen_helpers_test.rs"]
mod tests;
