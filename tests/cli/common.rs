// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common helpers for CLI integration tests
//!
//! This module provides shared helper functions and constants used across
//! CLI integration tests to reduce code duplication and improve maintainability.

use assert_cmd::{cargo, Command};
use kapsaro_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;
use kapsaro_core::cli_api::test_support::wire::schema::document::parse_kv_signature_token;
use kapsaro_core::cli_api::test_support::wire::token::TokenCodec;
pub use kapsaro_test_support::constants::{
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, CAROL_MEMBER_HANDLE, TEST_MEMBER_HANDLE,
};
use kapsaro_test_support::fixture::generate_temp_ssh_keypair_in_dir;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Command as StdCommand, ExitStatus, Stdio};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[derive(Clone, Debug, Default)]
pub struct CommonOptions {
    pub home: Option<PathBuf>,
    pub identity: Option<PathBuf>,
    pub json: bool,
    pub quiet: bool,
    pub workspace: Option<PathBuf>,
}

// ============================================================================
// Test Binary Helper
// ============================================================================

/// Helper to get the kapsaro test binary command.
///
/// Sets `KAPSARO_SSH_SIGNING_METHOD=ssh-keygen` for CLI integration tests.
pub fn cmd() -> Command {
    let mut c = cargo::cargo_bin_cmd!("kapsaro");
    c.env("KAPSARO_SSH_SIGNING_METHOD", "ssh-keygen");
    c
}

pub fn tamper_kv_signature(path: &Path) {
    let content = std::fs::read_to_string(path).expect("kv-enc file must be readable");
    let mut lines = Vec::new();
    let mut tampered = false;
    for line in content.lines() {
        if let Some(token) = line.strip_prefix(":SIG ") {
            let mut signature =
                parse_kv_signature_token(token).expect("kv-enc signature token must parse");
            signature.sig = encode_base64url_nopad(&[0u8; 64]);
            let token = TokenCodec::encode(TokenCodec::JsonJcs, &signature)
                .expect("tampered signature token must encode");
            lines.push(format!(":SIG {token}"));
            tampered = true;
        } else {
            lines.push(line.to_string());
        }
    }
    assert!(tampered, "kv-enc file must contain a SIG line");
    std::fs::write(path, format!("{}\n", lines.join("\n"))).expect("kv-enc file must be writable");
}

#[cfg(unix)]
pub struct PtyCommandResult {
    pub status: ExitStatus,
    pub output: String,
}

#[cfg(unix)]
pub fn kapsaro_bin() -> PathBuf {
    PathBuf::from(
        std::env::var_os("CARGO_BIN_EXE_kapsaro")
            .expect("CARGO_BIN_EXE_kapsaro must be set for integration tests"),
    )
}

#[cfg(unix)]
pub fn kapsaro_std_cmd() -> StdCommand {
    let mut command = StdCommand::new(kapsaro_bin());
    command.env("KAPSARO_SSH_SIGNING_METHOD", "ssh-keygen");
    command
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

#[cfg(unix)]
pub fn run_command_with_pty_script(
    command: &mut StdCommand,
    prompts: &[(&str, &[u8])],
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

    for (prompt, input) in prompts {
        wait_for_prompt(
            &mut child,
            &mut master,
            &mut transcript,
            prompt,
            Duration::from_secs(10),
        );
        thread::sleep(Duration::from_millis(25));
        master
            .write_all(input)
            .expect("PTY input write must succeed");
    }

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

#[cfg(unix)]
fn run_command_with_optional_prompt_pty(
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

    if let Some(status) = wait_for_prompt_or_exit(
        &mut child,
        &mut master,
        &mut transcript,
        prompt,
        Duration::from_secs(10),
    ) {
        load_available(&mut master, &mut transcript);
        return PtyCommandResult {
            status,
            output: String::from_utf8_lossy(&transcript).into_owned(),
        };
    }
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

fn run_command_with_optional_prompt_pty_after_input(
    command: &mut StdCommand,
    initial_input: &[u8],
    prompt: &str,
    prompt_input: &[u8],
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

    master
        .write_all(initial_input)
        .expect("PTY initial input write must succeed");
    if let Some(status) = wait_for_prompt_or_exit(
        &mut child,
        &mut master,
        &mut transcript,
        prompt,
        Duration::from_secs(10),
    ) {
        load_available(&mut master, &mut transcript);
        return PtyCommandResult {
            status,
            output: String::from_utf8_lossy(&transcript).into_owned(),
        };
    }
    master
        .write_all(prompt_input)
        .expect("PTY prompt input write must succeed");

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

#[cfg(unix)]
pub fn assert_member_set_review_success(command: &mut StdCommand) -> String {
    let result = run_command_with_optional_prompt_pty(command, "member set", b"y\r");
    assert!(
        result.status.success(),
        "command failed while accepting or skipping member set review:\n{}",
        result.output
    );
    result.output
}

#[cfg(unix)]
pub fn assert_stdin_member_set_review_success(
    command: &mut StdCommand,
    stdin_content: &[u8],
) -> String {
    let mut input = stdin_content.to_vec();
    input.push(b'\n');
    input.push(0x04);
    let result =
        run_command_with_optional_prompt_pty_after_input(command, &input, "member set", b"y\r");
    assert!(
        result.status.success(),
        "command failed while accepting or skipping stdin member set review:\n{}",
        result.output
    );
    result.output
}

#[cfg(unix)]
pub fn set_value_with_member_set_review(
    workspace: &Path,
    home: &Path,
    ssh_identity: &Path,
    key: &str,
    value: &str,
    member_handle: Option<&str>,
    name: Option<&str>,
) {
    let mut command = kapsaro_std_cmd();
    command
        .arg("set")
        .arg(key)
        .arg(value)
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    if let Some(member_handle) = member_handle {
        command.arg("--member-handle").arg(member_handle);
    }
    if let Some(name) = name {
        command.arg("--name").arg(name);
    }
    assert_member_set_review_success(&mut command);
}

#[cfg(unix)]
pub fn set_stdin_with_member_set_review(
    workspace: &Path,
    home: &Path,
    ssh_identity: &Path,
    key: &str,
    value: &[u8],
    member_handle: Option<&str>,
    name: Option<&str>,
) {
    let mut command = kapsaro_std_cmd();
    command
        .arg("set")
        .arg(key)
        .arg("--stdin")
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    if let Some(member_handle) = member_handle {
        command.arg("--member-handle").arg(member_handle);
    }
    if let Some(name) = name {
        command.arg("--name").arg(name);
    }
    assert_stdin_member_set_review_success(&mut command, value);
}

#[cfg(unix)]
pub fn encrypt_file_with_member_set_review(
    workspace: &Path,
    home: &Path,
    ssh_identity: &Path,
    input: &Path,
    output: &Path,
    member_handle: &str,
) -> String {
    let mut command = kapsaro_std_cmd();
    command
        .arg("encrypt")
        .arg(input)
        .arg("--out")
        .arg(output)
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    assert_member_set_review_success(&mut command)
}

#[cfg(unix)]
pub fn encrypt_stdin_with_member_set_review(
    workspace: &Path,
    home: &Path,
    ssh_identity: &Path,
    input: &[u8],
    output: Option<&Path>,
    stdout: bool,
    member_handle: &str,
) -> String {
    let mut command = kapsaro_std_cmd();
    command
        .arg("encrypt")
        .arg("--stdin")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    if let Some(output) = output {
        command.arg("--out").arg(output);
    }
    if stdout {
        command.arg("--stdout");
    }
    assert_stdin_member_set_review_success(&mut command, input)
}

#[cfg(unix)]
pub fn import_file_with_member_set_review(
    workspace: &Path,
    home: &Path,
    ssh_identity: &Path,
    input: &Path,
    json: bool,
) -> String {
    let mut command = kapsaro_std_cmd();
    command
        .arg("import")
        .arg(input)
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    if json {
        command.arg("--json");
    }
    assert_member_set_review_success(&mut command)
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
        json: false,
        quiet: false,
    }
}

/// Helper to set SSH key path in CommonOptions from temp_dir
pub fn set_ssh_key_from_temp_dir(common_opts: &mut CommonOptions, temp_dir: &TempDir) {
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");
    common_opts.identity = Some(ssh_key_path);
}

#[cfg(unix)]
pub fn append_common_command_args(command: &mut StdCommand, common_opts: &CommonOptions) {
    if let Some(workspace) = &common_opts.workspace {
        command.arg("--workspace").arg(workspace);
    }
    if common_opts.json {
        command.arg("--json");
    }
    if common_opts.quiet {
        command.arg("--quiet");
    }
    if let Some(home) = &common_opts.home {
        command.env("KAPSARO_HOME", home);
    }
    if let Some(identity) = &common_opts.identity {
        command.env("KAPSARO_SSH_IDENTITY", identity);
    }
}

pub fn assert_stderr_order(stderr: &[u8], first: &str, second: &str) {
    let stderr = String::from_utf8_lossy(stderr);
    let first_index = stderr
        .find(first)
        .unwrap_or_else(|| panic!("Missing '{first}' in stderr: {stderr}"));
    let second_index = stderr
        .find(second)
        .unwrap_or_else(|| panic!("Missing '{second}' in stderr: {stderr}"));
    assert!(
        first_index < second_index,
        "Expected '{first}' before '{second}' in stderr: {stderr}"
    );
}

pub fn copy_dir_all(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let file_type = entry.file_type().unwrap();
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&source_path, &destination_path);
        } else {
            std::fs::copy(&source_path, &destination_path).unwrap();
        }
    }
}

pub fn make_secret_home() -> TempDir {
    let home_dir = TempDir::new().unwrap();
    set_secret_home_permissions(&home_dir);
    home_dir
}

#[cfg(unix)]
fn set_secret_home_permissions(home_dir: &TempDir) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(home_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
fn set_secret_home_permissions(_home_dir: &TempDir) {}

/// Helper to create a workspace with initialized member.
///
/// Returns: (workspace_dir, home_dir, ssh_temp, ssh_priv_path)
pub fn setup_workspace() -> (TempDir, TempDir, TempDir, PathBuf) {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    std::fs::create_dir_all(workspace_dir.path().join("members")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    let output = cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("failed to initialize test workspace: {}", stderr.trim());
    }

    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}

#[cfg(unix)]
pub fn setup_workspace_with_kv_entries(
    entries: &[(&str, &str)],
) -> (TempDir, TempDir, TempDir, PathBuf) {
    let (workspace_dir, home_dir, ssh_temp, ssh_priv) = setup_workspace();
    for (key, value) in entries {
        set_value_with_member_set_review(
            workspace_dir.path(),
            home_dir.path(),
            &ssh_priv,
            key,
            value,
            None,
            None,
        );
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
fn wait_for_prompt_or_exit(
    child: &mut std::process::Child,
    master: &mut File,
    transcript: &mut Vec<u8>,
    prompt: &str,
    timeout: Duration,
) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        load_available(master, transcript);
        if String::from_utf8_lossy(transcript).contains(prompt) {
            return None;
        }

        if let Some(status) = child.try_wait().expect("child status check must succeed") {
            return Some(status);
        }

        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for prompt '{prompt}' or command exit\n{}",
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
