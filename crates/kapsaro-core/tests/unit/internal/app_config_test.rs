// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the config command orchestration.
//! Pins which command creates the local state home and which one only reads it.

use std::path::Path;

use crate::test_utils::{create_local_state_dir, local_state_temp_dir, write_local_state_file};
use crate::ErrorKind;

use super::{set_config, unset_config, LocalStateSession};

fn missing_home(parent: &Path) -> std::path::PathBuf {
    parent.join("absent-local-state")
}

#[test]
fn set_config_creates_the_local_state_home() {
    let temp_dir = local_state_temp_dir();
    let home = missing_home(temp_dir.path());

    let result = set_config(&home, "workspace", "/tmp/workspace").unwrap();

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
    set_config(&home, "workspace", "/tmp/workspace").unwrap();

    let result = unset_config("workspace", &home).unwrap();

    assert_eq!(result.key, "workspace");
    let error = unset_config("workspace", &home).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[test]
fn test_local_state_session_invalid_config_load_error() {
    let home = local_state_temp_dir();
    write_local_state_file(&home.path().join("config.toml"), "member_handle = [\n");

    let session = LocalStateSession::open(home.path()).expect("opening home must not parse config");
    let error = session.load_config().unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(error
        .format_user_message()
        .contains("Invalid TOML in config file"));
}

#[test]
fn test_local_state_session_first_load_fixes_config() {
    let home = local_state_temp_dir();
    let config_path = home.path().join("config.toml");
    write_local_state_file(&config_path, "member_handle = \"alice@example.com\"\n");
    let session = LocalStateSession::open(home.path()).expect("open local state");

    assert_eq!(
        session.load_config().unwrap().get("member_handle"),
        Some(&"alice@example.com".to_string())
    );
    write_local_state_file(&config_path, "member_handle = \"bob@example.com\"\n");

    assert_eq!(
        session.load_config().unwrap().get("member_handle"),
        Some(&"alice@example.com".to_string())
    );
}

#[test]
fn test_local_state_session_absent_home_fixes_empty_config() {
    let parent = local_state_temp_dir();
    let home = parent.path().join("absent-home");
    let session = LocalStateSession::open(&home).expect("observe absent local state");
    create_local_state_dir(&home);
    write_local_state_file(
        &home.join("config.toml"),
        "member_handle = \"alice@example.com\"\n",
    );

    assert!(session.load_config().unwrap().is_empty());
}
