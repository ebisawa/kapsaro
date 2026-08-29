// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for the guard helpers shared by the workspace test trees.
//! Covers `lock_unpoisoned` and the restore-on-unwind contract of the cwd and env guards.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

use kapsaro_test_support::guards::{lock_unpoisoned, with_temp_cwd, EnvGuard};

/// Environment variables reserved for the guard tests below. Each test owns its
/// own name so the tests stay independent without nesting `EnvGuard`, which
/// would deadlock on the single global env mutex.
const PRESENT_VAR: &str = "KAPSARO_TEST_SUPPORT_GUARD_PRESENT";
const ABSENT_VAR: &str = "KAPSARO_TEST_SUPPORT_GUARD_ABSENT";
#[cfg(unix)]
const NON_UTF8_VAR: &str = "KAPSARO_TEST_SUPPORT_GUARD_NON_UTF8";

/// Serializes the process-global panic hook swap in `catch_silent_panic`.
static HOOK_LOCK: Mutex<()> = Mutex::new(());

/// Run a closure that is expected to panic without letting the default panic
/// hook print a backtrace into the test log.
fn catch_silent_panic(f: impl FnOnce()) {
    let _hook_lock = lock_unpoisoned(&HOOK_LOCK);
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(previous);
    assert!(outcome.is_err(), "closure was expected to panic");
}

#[test]
fn test_lock_unpoisoned_returns_guard_for_healthy_mutex() {
    let mutex = Mutex::new(42_u8);
    let guard = lock_unpoisoned(&mutex);
    assert_eq!(*guard, 42);
}

#[test]
fn test_lock_unpoisoned_recovers_from_a_poisoned_mutex() {
    let mutex = Mutex::new(7_u8);
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = mutex.lock().unwrap();
        panic!("poison the mutex");
    }));

    let guard = lock_unpoisoned(&mutex);

    assert_eq!(*guard, 7);
}

#[test]
fn test_with_temp_cwd_enters_the_requested_directory() {
    let temp = tempfile::tempdir().unwrap();
    let expected = temp.path().canonicalize().unwrap();

    let observed = with_temp_cwd(temp.path(), || std::env::current_dir().unwrap());

    assert_eq!(observed.canonicalize().unwrap(), expected);
}

#[test]
fn test_with_temp_cwd_restores_the_directory_when_the_closure_panics() {
    // The current directory is process-global, so restoring only on the success
    // path would leak a deleted temporary directory into every later test.
    let original = std::env::current_dir().unwrap();
    let temp = tempfile::tempdir().unwrap();

    catch_silent_panic(|| {
        with_temp_cwd(temp.path(), || {
            panic!("failing assertion inside the closure")
        });
    });

    assert_eq!(std::env::current_dir().unwrap(), original);
}

#[test]
fn test_env_guard_restores_a_preexisting_value_when_the_closure_panics() {
    std::env::set_var(PRESENT_VAR, "original");

    catch_silent_panic(|| {
        let _guard = EnvGuard::new(&[PRESENT_VAR]);
        std::env::set_var(PRESENT_VAR, "overwritten");
        panic!("failing assertion while the variable is overwritten");
    });

    assert_eq!(std::env::var(PRESENT_VAR).unwrap(), "original");
    std::env::remove_var(PRESENT_VAR);
}

#[test]
fn test_env_guard_clears_a_variable_it_introduced_when_the_closure_panics() {
    std::env::remove_var(ABSENT_VAR);

    catch_silent_panic(|| {
        let _guard = EnvGuard::new(&[ABSENT_VAR]);
        std::env::set_var(ABSENT_VAR, "introduced");
        panic!("failing assertion after introducing the variable");
    });

    assert_eq!(
        std::env::var(ABSENT_VAR),
        Err(std::env::VarError::NotPresent)
    );
}

#[cfg(unix)]
#[test]
fn test_env_guard_restores_a_non_utf8_value_when_the_closure_panics() {
    use std::os::unix::ffi::OsStringExt;

    let original = std::ffi::OsString::from_vec(vec![b'p', b'a', b't', b'h', 0xff]);
    std::env::set_var(NON_UTF8_VAR, &original);

    catch_silent_panic(|| {
        let _guard = EnvGuard::new(&[NON_UTF8_VAR]);
        std::env::set_var(NON_UTF8_VAR, "overwritten");
        panic!("failing assertion while the variable is overwritten");
    });

    assert_eq!(std::env::var_os(NON_UTF8_VAR), Some(original));
    std::env::remove_var(NON_UTF8_VAR);
}
