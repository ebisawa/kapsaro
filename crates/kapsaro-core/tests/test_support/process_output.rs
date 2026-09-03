// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Synthesized process results for testing output handling without spawning.
// Lets error and decoding paths be exercised as pure functions.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};

/// Build a process result from a raw wait status and the captured streams.
pub fn build_process_output(code: i32, stderr: &[u8], stdout: &[u8]) -> Output {
    Output {
        status: ExitStatus::from_raw(code),
        stderr: stderr.to_vec(),
        stdout: stdout.to_vec(),
    }
}

/// Raw wait status for a process that exited with code 1.
///
/// A wait status carries the exit code in its upper byte, so the raw value is
/// `1 << 8` rather than `1`.
pub fn failed_code() -> i32 {
    256
}

/// Save an executable that prints the child process's SSH agent socket.
pub fn save_agent_socket_echo_script(directory: &Path, name: &str) -> PathBuf {
    let script = directory.join(name);
    std::fs::write(&script, "#!/bin/sh\nprintf '%s\\n' \"$SSH_AUTH_SOCK\"\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    script
}
