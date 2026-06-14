// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Test helpers for process umask-sensitive filesystem assertions.
//! Runs umask mutations in isolated test child processes.

#[cfg(unix)]
pub(crate) fn run_current_test_in_isolated_umask_process(env_name: &str, test_name: &str) -> bool {
    if std::env::var_os(env_name).is_some() {
        return false;
    }

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(env_name, "1")
        .status()
        .unwrap();
    assert!(status.success(), "umask child test failed: {status}");
    true
}

#[cfg(unix)]
pub(crate) fn with_restrictive_umask(run: impl FnOnce()) {
    let previous = unsafe { libc::umask(0o777) };
    let guard = UmaskGuard(previous);
    run();
    drop(guard);
}

#[cfg(unix)]
struct UmaskGuard(libc::mode_t);

#[cfg(unix)]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.0);
        }
    }
}
