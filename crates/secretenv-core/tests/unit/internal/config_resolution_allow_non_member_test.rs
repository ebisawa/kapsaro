// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::test_utils::EnvGuard;

use super::resolve_allow_non_member;

#[test]
fn defaults_to_disallow_non_member_acceptance() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_ALLOW_NON_MEMBER"]);
    let tmp = tempfile::tempdir().unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(tmp.path().to_str().unwrap())),
            ("SECRETENV_ALLOW_NON_MEMBER", None),
        ],
        || assert!(!resolve_allow_non_member(None, Some(tmp.path())).unwrap()),
    );
}

#[test]
fn cli_allow_overrides_env_and_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_ALLOW_NON_MEMBER"]);
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "allow_non_member = \"no\"\n",
    )
    .unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(tmp.path().to_str().unwrap())),
            ("SECRETENV_ALLOW_NON_MEMBER", Some("no")),
        ],
        || assert!(resolve_allow_non_member(Some(true), Some(tmp.path())).unwrap()),
    );
}

#[test]
fn env_overrides_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_ALLOW_NON_MEMBER"]);
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "allow_non_member = \"no\"\n",
    )
    .unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(tmp.path().to_str().unwrap())),
            ("SECRETENV_ALLOW_NON_MEMBER", Some("YES")),
        ],
        || assert!(resolve_allow_non_member(None, Some(tmp.path())).unwrap()),
    );
}

#[test]
fn reads_config_value() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_ALLOW_NON_MEMBER"]);
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "allow_non_member = \"yes\"\n",
    )
    .unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(tmp.path().to_str().unwrap())),
            ("SECRETENV_ALLOW_NON_MEMBER", None),
        ],
        || assert!(resolve_allow_non_member(None, Some(tmp.path())).unwrap()),
    );
}

#[test]
fn invalid_value_is_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_ALLOW_NON_MEMBER"]);
    let tmp = tempfile::tempdir().unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(tmp.path().to_str().unwrap())),
            ("SECRETENV_ALLOW_NON_MEMBER", Some("maybe")),
        ],
        || assert!(resolve_allow_non_member(None, Some(tmp.path())).is_err()),
    );
}
