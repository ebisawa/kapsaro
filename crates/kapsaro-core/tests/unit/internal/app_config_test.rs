// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the config command orchestration.
//! Pins which command creates the local state home and which one only reads it.

use std::path::Path;

use crate::test_utils::local_state_temp_dir;
use crate::ErrorKind;

use super::{set_config, unset_config};

fn missing_home(parent: &Path) -> std::path::PathBuf {
    parent.join("absent-local-state")
}

#[test]
fn set_config_creates_the_local_state_home() {
    let temp_dir = local_state_temp_dir();
    let home = missing_home(temp_dir.path());

    let result = set_config("workspace", "/tmp/workspace", &home).unwrap();

    assert_eq!(result.key, "workspace");
    assert!(home.is_dir());
}

#[test]
fn unset_config_reports_a_missing_key_when_the_home_is_absent() {
    let temp_dir = local_state_temp_dir();
    let home = missing_home(temp_dir.path());

    let error = unset_config("workspace", &home).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert!(error
        .format_user_message()
        .contains("Configuration key 'workspace' not found"));
    assert!(!home.try_exists().unwrap());
}

#[test]
fn unset_config_removes_a_value_from_an_existing_home() {
    let temp_dir = local_state_temp_dir();
    let home = missing_home(temp_dir.path());
    set_config("workspace", "/tmp/workspace", &home).unwrap();

    let result = unset_config("workspace", &home).unwrap();

    assert_eq!(result.key, "workspace");
    let error = unset_config("workspace", &home).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
}
