// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Minimal helpers for CLI internal unit tests.
//! These helpers avoid pulling the full integration-test fixture module into the library test target.

use kapsaro_core::cli_api::test_support::domain::identity::MemberHandle;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// Create a temporary directory usable as `<KAPSARO_HOME>`.
///
/// `TempDir::new` honours the process umask, so a bare temporary directory is
/// group-readable under the usual 022 and local state refuses it.
pub(crate) fn local_state_temp_dir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("create local state temp dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict local state temp dir");
    }
    dir
}

/// Write a local state file with the owner-only permissions its loader requires.
///
/// Local state refuses any file group or other can reach, so a fixture written
/// under the developer's umask would fail before the test reached its subject.
pub(crate) fn write_local_state_file(path: &Path, contents: impl AsRef<[u8]>) {
    std::fs::write(path, contents).expect("write local state fixture file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict local state fixture file");
    }
}

pub(crate) fn member_handle(value: impl Into<String>) -> MemberHandle {
    MemberHandle::try_from(value.into()).expect("test member_handle must be valid")
}

static ENV_MUTEX: Mutex<()> = Mutex::new(());

pub(crate) struct EnvGuard {
    vars: Vec<(String, Option<String>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub(crate) fn new(keys: &[&str]) -> Self {
        let lock = lock_unpoisoned(&ENV_MUTEX);
        let vars = keys
            .iter()
            .map(|&key| (key.to_string(), std::env::var(key).ok()))
            .collect();
        Self { vars, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.vars {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
