// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// RAII guards for the process-global current directory and environment.
// Each test binary gets its own locks, which is what serialization needs.

use std::path::Path;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct CwdGuard {
    original: PathBuf,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl CwdGuard {
    fn enter(dir: &Path) -> Self {
        let lock = lock_unpoisoned(CWD_LOCK.get_or_init(|| Mutex::new(())));
        let original = std::env::current_dir().unwrap();
        // This guard is the serialized entry point the lint points callers at,
        // so the raw call has to live here.
        #[allow(clippy::disallowed_methods)]
        std::env::set_current_dir(dir).unwrap();
        Self {
            original,
            _lock: lock,
        }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        // Restoring the directory this guard changed, still under CWD_LOCK.
        #[allow(clippy::disallowed_methods)]
        let _ = std::env::set_current_dir(&self.original);
    }
}

/// Run a closure with the process current directory temporarily changed.
///
/// This is serialized via a global mutex because the current directory is
/// process-global and Rust tests run in parallel by default.
pub fn with_temp_cwd<R>(dir: &Path, f: impl FnOnce() -> R) -> R {
    let _guard = CwdGuard::enter(dir);
    f()
}

/// Global mutex for tests that modify environment variables.
/// All tests that modify environment variables must hold this lock.
pub static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// RAII guard that holds the env mutex and restores env vars on drop.
pub struct EnvGuard {
    vars: Vec<(String, Option<std::ffi::OsString>)>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub fn new(keys: &[&str]) -> Self {
        let lock = lock_unpoisoned(&ENV_MUTEX);
        let vars = keys
            .iter()
            .map(|&k| (k.to_string(), std::env::var_os(k)))
            .collect();
        Self { vars, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.vars {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}
