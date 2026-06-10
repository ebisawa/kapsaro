// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Binary/command execution helpers and PTY (pseudo-terminal) infrastructure.
// Provides the test binary entry points and low-level interactive I/O primitives.

use assert_cmd::{cargo, Command};
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

/// Result of running a command through a PTY.
#[cfg(unix)]
pub struct PtyCommandResult {
    pub status: ExitStatus,
    pub output: String,
}

/// Helper to get the kapsaro test binary command.
///
/// Sets `KAPSARO_SSH_SIGNING_METHOD=ssh-keygen` for CLI integration tests.
pub fn cmd() -> Command {
    let mut c = cargo::cargo_bin_cmd!("kapsaro");
    c.env("KAPSARO_SSH_SIGNING_METHOD", "ssh-keygen");
    c
}

/// Returns the path to the kapsaro binary under test.
#[cfg(unix)]
pub fn kapsaro_bin() -> PathBuf {
    PathBuf::from(
        std::env::var_os("CARGO_BIN_EXE_kapsaro")
            .expect("CARGO_BIN_EXE_kapsaro must be set for integration tests"),
    )
}

/// Returns a `std::process::Command` for the kapsaro binary.
#[cfg(unix)]
pub fn kapsaro_std_cmd() -> StdCommand {
    let mut command = StdCommand::new(kapsaro_bin());
    command.env("KAPSARO_SSH_SIGNING_METHOD", "ssh-keygen");
    command
}

/// Runs a command through a PTY, waits for a single prompt, sends input, then waits for exit.
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

/// Runs a command through a PTY, stepping through multiple (prompt, input) pairs, then waits for exit.
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

/// Runs a command through a PTY; if the optional prompt appears sends input, otherwise returns early.
#[cfg(unix)]
pub(super) fn run_command_with_optional_prompt_pty(
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

/// Writes initial input, then handles an optional prompt before waiting for exit.
#[cfg(unix)]
pub(super) fn run_command_with_optional_prompt_pty_after_input(
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
pub(super) fn load_available(master: &mut File, transcript: &mut Vec<u8>) {
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
