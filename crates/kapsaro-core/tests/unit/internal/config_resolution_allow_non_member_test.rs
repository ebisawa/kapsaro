// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::test_utils::{local_state_temp_dir, write_local_state_file, EnvGuard};

use super::resolve_allow_non_member;

#[test]
fn defaults_to_disallow_non_member_acceptance() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_NON_MEMBER"]);
    let tmp = local_state_temp_dir();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::remove_var("KAPSARO_ALLOW_NON_MEMBER");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));
    assert!(!resolve_allow_non_member(None, &config).unwrap());
}

#[test]
fn cli_allow_overrides_env_and_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_NON_MEMBER"]);
    let tmp = local_state_temp_dir();
    write_local_state_file(
        &tmp.path().join("config.toml"),
        "allow_non_member = \"no\"\n",
    );

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_NON_MEMBER", "no");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));
    assert!(resolve_allow_non_member(Some(true), &config).unwrap());
}

#[test]
fn env_overrides_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_NON_MEMBER"]);
    let tmp = local_state_temp_dir();
    write_local_state_file(
        &tmp.path().join("config.toml"),
        "allow_non_member = \"no\"\n",
    );

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_NON_MEMBER", "YES");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));
    assert!(resolve_allow_non_member(None, &config).unwrap());
}

#[test]
fn reads_config_value() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_NON_MEMBER"]);
    let tmp = local_state_temp_dir();
    write_local_state_file(
        &tmp.path().join("config.toml"),
        "allow_non_member = \"yes\"\n",
    );

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::remove_var("KAPSARO_ALLOW_NON_MEMBER");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));
    assert!(resolve_allow_non_member(None, &config).unwrap());
}

#[test]
fn invalid_value_is_error() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_NON_MEMBER"]);
    let tmp = local_state_temp_dir();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_NON_MEMBER", "maybe");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));
    assert!(resolve_allow_non_member(None, &config).is_err());
}
