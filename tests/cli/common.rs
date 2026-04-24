// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common helpers for CLI integration tests
//!
//! This module provides shared helper functions and constants used across
//! CLI integration tests to reduce code duplication and improve maintainability.

use crate::test_utils::generate_temp_ssh_keypair_in_dir;
pub use crate::test_utils::{
    ALICE_MEMBER_ID, BOB_MEMBER_ID, CAROL_MEMBER_ID, DAVE_MEMBER_ID, EVE_MEMBER_ID,
    FRANK_MEMBER_ID, TEST_MEMBER_ID,
};
use assert_cmd::{cargo, Command};
use secretenv::cli::options::CommonOptions;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command as StdCommand, ExitStatus, Stdio};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};
use tempfile::TempDir;

// ============================================================================
// Test Binary Helper
// ============================================================================

/// Helper to get the secretenv test binary command.
///
/// Sets `SECRETENV_SSH_SIGNING_METHOD=ssh-keygen` for CLI integration tests.
pub fn cmd() -> Command {
    let mut c = cargo::cargo_bin_cmd!("secretenv");
    c.env("SECRETENV_SSH_SIGNING_METHOD", "ssh-keygen");
    c
}

#[cfg(unix)]
pub struct PtyCommandResult {
    pub status: ExitStatus,
    pub output: String,
}

#[cfg(unix)]
pub fn secretenv_bin() -> PathBuf {
    PathBuf::from(
        std::env::var_os("CARGO_BIN_EXE_secretenv")
            .expect("CARGO_BIN_EXE_secretenv must be set for integration tests"),
    )
}

#[cfg(unix)]
pub fn run_command_with_pty(
    command: &mut StdCommand,
    prompt: &str,
    input: &[u8],
) -> PtyCommandResult {
    let (mut master, slave) = open_pty_pair().expect("PTY must open for interactive CLI test");
    set_nonblocking(&master).expect("PTY master must support non-blocking reads");

    let stdin = slave
        .try_clone()
        .expect("PTY slave stdin clone must succeed");
    let stdout = slave
        .try_clone()
        .expect("PTY slave stdout clone must succeed");
    command.stdin(Stdio::from(stdin));
    command.stdout(Stdio::from(stdout));
    command.stderr(Stdio::from(slave));

    let mut child = command.spawn().expect("interactive CLI child must spawn");
    let mut transcript = Vec::new();

    wait_for_prompt(
        &mut child,
        &mut master,
        &mut transcript,
        prompt,
        Duration::from_secs(10),
    );
    master
        .write_all(input)
        .expect("PTY input write must succeed");

    let status = wait_for_exit(
        &mut child,
        &mut master,
        &mut transcript,
        Duration::from_secs(10),
    );
    PtyCommandResult {
        status,
        output: String::from_utf8_lossy(&transcript).into_owned(),
    }
}

// ============================================================================
// Test Constants
// ============================================================================

// ============================================================================
// Common Helper Functions
// ============================================================================

/// Helper to create default CommonOptions for testing.
///
/// Uses `ssh_keygen: true` so tests work in CI environments where
/// `SSH_AUTH_SOCK` is set but no keys are loaded in the agent.
pub fn default_common_options() -> CommonOptions {
    CommonOptions {
        home: None,
        workspace: None,
        identity: None,
        ssh_agent: false,
        ssh_keygen: true,
        json: false,
        quiet: false,
        verbose: false,
    }
}

/// Helper to set SSH key path in CommonOptions from temp_dir
pub fn set_ssh_key_from_temp_dir(common_opts: &mut CommonOptions, temp_dir: &TempDir) {
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");
    common_opts.identity = Some(ssh_key_path);
}

/// Helper to create a workspace with initialized member.
///
/// Returns: (workspace_dir, home_dir, ssh_temp, ssh_priv_path)
pub fn setup_workspace() -> (TempDir, TempDir, TempDir, PathBuf) {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    std::fs::create_dir_all(workspace_dir.path().join("members")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    let output = cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("failed to initialize test workspace: {}", stderr.trim());
    }

    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}

/// Helper to create a temporary SSH Ed25519 keypair for testing
///
/// Returns: (temp_dir, private_key_path, public_key_path, public_key_content)
pub fn generate_temp_ssh_keypair() -> (TempDir, PathBuf, PathBuf, String) {
    let temp_dir = TempDir::new().unwrap();
    let (private_key_path, public_key_path, public_key_content) =
        generate_temp_ssh_keypair_in_dir(&temp_dir);

    (
        temp_dir,
        private_key_path,
        public_key_path,
        public_key_content,
    )
}

#[cfg(unix)]
fn open_pty_pair() -> io::Result<(File, File)> {
    let mut master_fd = -1;
    let mut slave_fd = -1;
    let result = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }

    let master = unsafe { File::from_raw_fd(master_fd) };
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    Ok((master, slave))
}

#[cfg(unix)]
fn set_nonblocking(file: &File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }

    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn wait_for_prompt(
    child: &mut std::process::Child,
    master: &mut File,
    transcript: &mut Vec<u8>,
    prompt: &str,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        load_available(master, transcript);
        if String::from_utf8_lossy(transcript).contains(prompt) {
            return;
        }

        if let Some(status) = child.try_wait().expect("child status check must succeed") {
            panic!(
                "interactive CLI exited before prompt '{prompt}' appeared: {status}\n{}",
                String::from_utf8_lossy(transcript)
            );
        }

        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for prompt '{prompt}'\n{}",
                String::from_utf8_lossy(transcript)
            );
        }

        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn wait_for_exit(
    child: &mut std::process::Child,
    master: &mut File,
    transcript: &mut Vec<u8>,
    timeout: Duration,
) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        load_available(master, transcript);
        if let Some(status) = child.try_wait().expect("child status check must succeed") {
            load_available(master, transcript);
            return status;
        }

        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for interactive CLI to exit\n{}",
                String::from_utf8_lossy(transcript)
            );
        }

        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn load_available(master: &mut File, transcript: &mut Vec<u8>) {
    let mut buffer = [0_u8; 1024];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => return,
            Ok(bytes_read) => transcript.extend_from_slice(&buffer[..bytes_read]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            Err(error) if error.raw_os_error() == Some(libc::EIO) => return,
            Err(error) => panic!("failed to read PTY output: {error}"),
        }
    }
}
