// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::test_utils::EnvGuard;

use super::resolve_allow_non_member;

#[test]
fn defaults_to_disallow_non_member_acceptance() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_NON_MEMBER"]);
    let tmp = tempfile::tempdir().unwrap();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::remove_var("KAPSARO_ALLOW_NON_MEMBER");

    assert!(!resolve_allow_non_member(None, Some(tmp.path())).unwrap());
}

#[test]
fn cli_allow_overrides_env_and_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_NON_MEMBER"]);
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "allow_non_member = \"no\"\n",
    )
    .unwrap();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_NON_MEMBER", "no");

    assert!(resolve_allow_non_member(Some(true), Some(tmp.path())).unwrap());
}

#[test]
fn env_overrides_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_NON_MEMBER"]);
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "allow_non_member = \"no\"\n",
    )
    .unwrap();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_NON_MEMBER", "YES");

    assert!(resolve_allow_non_member(None, Some(tmp.path())).unwrap());
}

#[test]
fn reads_config_value() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_NON_MEMBER"]);
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "allow_non_member = \"yes\"\n",
    )
    .unwrap();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::remove_var("KAPSARO_ALLOW_NON_MEMBER");

    assert!(resolve_allow_non_member(None, Some(tmp.path())).unwrap());
}

#[test]
fn invalid_value_is_error() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_NON_MEMBER"]);
    let tmp = tempfile::tempdir().unwrap();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_NON_MEMBER", "maybe");

    assert!(resolve_allow_non_member(None, Some(tmp.path())).is_err());
}
