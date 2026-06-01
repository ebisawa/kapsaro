// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Minimal helpers for CLI internal unit tests.
//! These helpers avoid pulling the full integration-test fixture module into the library test target.

use kapsaro_core::cli_api::test_support::domain::identity::{Kid, MemberHandle};
use std::sync::{Mutex, MutexGuard};

pub(crate) fn member_handle(value: impl Into<String>) -> MemberHandle {
    MemberHandle::try_from(value.into()).expect("test member_handle must be valid")
}

pub(crate) fn kid(value: impl Into<String>) -> Kid {
    Kid::try_from(value.into()).expect("test kid must be valid")
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
