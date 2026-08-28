// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use super::CommonCommandOptions;
use crate::config::types::ConfigKey;
use crate::test_utils::write_local_state_file;
use tempfile::TempDir;

#[test]
fn test_operation_options_copies_allow_expired_key() {
    let mut options =
        CommonCommandOptions::new().with_home(Some(PathBuf::from("/tmp/kapsaro-home")));
    options.allow_expired_key = true;

    let operation_options = options.operation_options();

    assert!(operation_options.allow_expired_key());
}

#[test]
fn test_ensure_local_state_home_refuses_an_absence_already_fixed() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("missing");
    let options = CommonCommandOptions::new().with_home(Some(home.clone()));
    assert!(options.fixed_home().unwrap().is_none());

    let error = options.ensure_local_state_home().unwrap_err();

    assert!(error
        .format_user_message()
        .contains("already fixed as absent"));
    assert!(!home.exists());
}

#[test]
fn test_ensured_home_keeps_its_configuration_after_path_swap() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let options = CommonCommandOptions::new().with_home(Some(home.clone()));
    options.ensure_local_state_home().unwrap();
    let opened = temp.path().join("opened");
    std::fs::rename(&home, &opened).unwrap();
    std::fs::create_dir(&home).unwrap();
    write_local_state_file(
        &opened.join("config.toml"),
        "github_user = \"started-in\"\n",
    );
    write_local_state_file(&home.join("config.toml"), "github_user = \"replacement\"\n");

    let github_user = options
        .global_config()
        .unwrap()
        .get(ConfigKey::GithubUser.canonical_name())
        .unwrap();

    assert_eq!(github_user.as_deref(), Some("started-in"));
}
