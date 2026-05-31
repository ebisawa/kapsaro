// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for KAPSARO_STRICT_KEY_CHECKING resolution

use crate::config::types::{
    StrictKeyChecking, StrictKeyCheckingResolution, StrictKeyCheckingSource,
};
use crate::test_utils::EnvGuard;

use super::resolve_strict_key_checking;

#[test]
fn test_strict_key_checking_default_is_yes() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    assert_eq!(
        resolve_strict_key_checking(),
        StrictKeyCheckingResolution::strict()
    );
}

#[test]
fn test_strict_key_checking_yes() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "yes");
    assert_eq!(
        resolve_strict_key_checking(),
        StrictKeyCheckingResolution {
            mode: StrictKeyChecking::Yes,
            source: StrictKeyCheckingSource::ExplicitEnv,
        }
    );
}

#[test]
fn test_strict_key_checking_no() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "no");
    assert_eq!(
        resolve_strict_key_checking(),
        StrictKeyCheckingResolution::explicit(StrictKeyChecking::No)
    );
}

#[test]
fn test_strict_key_checking_case_insensitive() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "NO");
    assert_eq!(
        resolve_strict_key_checking(),
        StrictKeyCheckingResolution::explicit(StrictKeyChecking::No)
    );
}

#[test]
fn test_strict_key_checking_invalid_value_defaults_to_yes() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "maybe");
    assert_eq!(
        resolve_strict_key_checking(),
        StrictKeyCheckingResolution::strict()
    );
}
