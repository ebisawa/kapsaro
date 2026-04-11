// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Default implementation of the `SshKeygen` trait using the system ssh-keygen command.

use super::traits::SshKeygen;
use super::{build_ssh_child_env, temp_file};
use crate::io::process::configure_child_env_os;
use crate::io::ssh::agent::socket::resolve_agent_socket_path;
use crate::io::ssh::SshError;
use crate::support::fs::load_text;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

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
        configure_child_env_os(
            &mut command,
            &build_ssh_child_env(resolve_agent_socket_path().ok().as_deref()),
        );

        let output = command
            .args(["-y", "-f"])
            .arg(key_path)
            .output()
            .map_err(|e| {
                Error::from(SshError::operation_failed_with_source(
                    "Failed to execute ssh-keygen",
                    e,
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(
                SshError::operation_failed(format!("ssh-keygen -y -f failed: {}", stderr)).into(),
            );
        }

        String::from_utf8(output.stdout)
            .map(|s| s.trim().to_string())
            .map_err(|e| {
                Error::from(SshError::operation_failed_with_source(
                    "Invalid UTF-8 in ssh-keygen output",
                    e,
                ))
            })
    }

    fn sign(&self, key_path: &Path, namespace: &str, data: &[u8]) -> Result<String> {
        let is_public_key = key_path
            .extension()
            .map(|ext| ext == "pub")
            .unwrap_or(false);

        let key_path_str = key_path.to_str().ok_or_else(|| {
            Error::from(SshError::operation_failed(format!(
                "SSH key path contains invalid UTF-8: {}",
                display_path_relative_to_cwd(key_path)
            )))
        })?;

        let msg_file = temp_file::save_temp_bytes(data)?;
        let output =
            execute_sign_command(&self.ssh_keygen_path, key_path_str, namespace, &msg_file)?;
        check_sign_output(&output, is_public_key)?;
        load_signature_file(&msg_file)
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
        configure_child_env_os(
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
                Error::from(SshError::operation_failed_with_source(
                    "Failed to spawn ssh-keygen",
                    e,
                ))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(message).map_err(|e| {
                Error::from(SshError::operation_failed_with_source(
                    "Failed to write to stdin",
                    e,
                ))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            Error::from(SshError::operation_failed_with_source(
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
    msg_file: &tempfile::NamedTempFile,
) -> Result<std::process::Output> {
    // Remove any pre-existing .sig file to prevent ssh-keygen from prompting
    // "Overwrite (y/n)?". When stdin is closed (as with Command::output()),
    // ssh-keygen silently skips writing on EOF, returning exit 0 with stale
    // content — which can cause false non-determinism errors.
    let sig_path = build_sig_path(msg_file);
    let _ = std::fs::remove_file(&sig_path);

    let mut command = Command::new(ssh_keygen_path);
    configure_child_env_os(
        &mut command,
        &build_ssh_child_env(resolve_agent_socket_path().ok().as_deref()),
    );

    command
        .args(["-Y", "sign"])
        .args(["-f", key_path_str])
        .args(["-n", namespace])
        .args(["-O", "hashalg=sha256"])
        .arg(msg_file.path())
        .output()
        .map_err(|e| {
            Error::from(SshError::operation_failed_with_source(
                format!(
                    "ssh-keygen command failed: {}\n\
                    Diagnostic: Ensure '{}' supports '-Y sign' (OpenSSH 8.0+).",
                    e, ssh_keygen_path
                ),
                e,
            ))
        })
}

fn build_sig_path(msg_file: &tempfile::NamedTempFile) -> std::path::PathBuf {
    let mut sig_path_str = msg_file.path().to_string_lossy().into_owned();
    sig_path_str.push_str(".sig");
    std::path::PathBuf::from(sig_path_str)
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
    Err(SshError::operation_failed(format!(
        "ssh-keygen -Y sign failed: {}\nHint: {}",
        stderr, hint
    ))
    .into())
}

fn load_signature_file(msg_file: &tempfile::NamedTempFile) -> Result<String> {
    load_text(&build_sig_path(msg_file))
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
    Err(
        SshError::operation_failed(format!("ssh-keygen -Y verify failed: {}", details.trim()))
            .into(),
    )
}

#[cfg(test)]
#[path = "../../../../tests/unit/ssh_external_keygen_helpers_test.rs"]
mod tests;
