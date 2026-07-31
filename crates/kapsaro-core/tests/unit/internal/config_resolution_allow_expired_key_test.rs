// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::test_utils::EnvGuard;

use super::resolve_allow_expired_key;

#[test]
fn defaults_to_disallow_expired_keys() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = tempfile::tempdir().unwrap();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::remove_var("KAPSARO_ALLOW_EXPIRED_KEY");

    assert!(!resolve_allow_expired_key(None, Some(tmp.path())).unwrap());
}

#[test]
fn cli_allow_overrides_env_and_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "allow_expired_key = \"no\"\n",
    )
    .unwrap();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_EXPIRED_KEY", "no");

    assert!(resolve_allow_expired_key(Some(true), Some(tmp.path())).unwrap());
}

#[test]
fn env_overrides_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "allow_expired_key = \"no\"\n",
    )
    .unwrap();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_EXPIRED_KEY", "YES");

    assert!(resolve_allow_expired_key(None, Some(tmp.path())).unwrap());
}

#[test]
fn reads_config_value() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "allow_expired_key = \"yes\"\n",
    )
    .unwrap();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::remove_var("KAPSARO_ALLOW_EXPIRED_KEY");

    assert!(resolve_allow_expired_key(None, Some(tmp.path())).unwrap());
}

#[test]
fn invalid_value_is_error() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = tempfile::tempdir().unwrap();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_EXPIRED_KEY", "maybe");

    assert!(resolve_allow_expired_key(None, Some(tmp.path())).is_err());
}
