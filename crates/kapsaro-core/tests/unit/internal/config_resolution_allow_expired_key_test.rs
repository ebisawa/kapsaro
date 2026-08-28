// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::test_utils::{local_state_temp_dir, write_local_state_file, EnvGuard};

use super::resolve_allow_expired_key;

#[test]
fn defaults_to_disallow_expired_keys() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = local_state_temp_dir();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::remove_var("KAPSARO_ALLOW_EXPIRED_KEY");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));
    assert!(!resolve_allow_expired_key(None, &config).unwrap());
}

#[test]
fn cli_allow_overrides_env_and_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = local_state_temp_dir();
    write_local_state_file(
        &tmp.path().join("config.toml"),
        "allow_expired_key = \"no\"\n",
    );

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_EXPIRED_KEY", "no");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));
    assert!(resolve_allow_expired_key(Some(true), &config).unwrap());
}

#[test]
fn env_overrides_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = local_state_temp_dir();
    write_local_state_file(
        &tmp.path().join("config.toml"),
        "allow_expired_key = \"no\"\n",
    );

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_EXPIRED_KEY", "YES");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));
    assert!(resolve_allow_expired_key(None, &config).unwrap());
}

#[test]
fn reads_config_value() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = local_state_temp_dir();
    write_local_state_file(
        &tmp.path().join("config.toml"),
        "allow_expired_key = \"yes\"\n",
    );

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::remove_var("KAPSARO_ALLOW_EXPIRED_KEY");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));
    assert!(resolve_allow_expired_key(None, &config).unwrap());
}

#[test]
fn invalid_value_is_error() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = local_state_temp_dir();

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::set_var("KAPSARO_ALLOW_EXPIRED_KEY", "maybe");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));
    assert!(resolve_allow_expired_key(None, &config).is_err());
}

/// One snapshot answers every later lookup from what it read the first time,
/// so a resolver handed the same snapshot twice reaches the same verdict.
#[test]
fn one_snapshot_answers_repeated_lookups() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_ALLOW_EXPIRED_KEY"]);
    let tmp = local_state_temp_dir();
    write_local_state_file(
        &tmp.path().join("config.toml"),
        "allow_expired_key = \"yes\"\n",
    );

    std::env::set_var("KAPSARO_HOME", tmp.path());
    std::env::remove_var("KAPSARO_ALLOW_EXPIRED_KEY");

    let config = GlobalConfigSnapshot::for_base_dir(Some(tmp.path()));

    assert!(resolve_allow_expired_key(None, &config).unwrap());
    assert!(resolve_allow_expired_key(None, &config).unwrap());
}
