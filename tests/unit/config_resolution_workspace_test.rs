// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::EnvGuard;
use std::fs;

#[test]
fn returns_none_when_no_workspace_in_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "HOME"]);
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");
    fs::write(
        &config_path,
        "format = \"secretenv/config@1\"\nmember_id = \"alice\"\n",
    )
    .unwrap();

    temp_env::with_vars(
        [("SECRETENV_HOME", Some(tmp.path().to_str().unwrap()))],
        || {
            let result = resolve_workspace_from_config().unwrap();
            assert!(result.is_none());
        },
    );
}

#[test]
fn returns_path_when_workspace_in_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "HOME"]);
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");
    fs::write(
        &config_path,
        "format = \"secretenv/config@1\"\nworkspace = \"/tmp/test-workspace/.secretenv\"\n",
    )
    .unwrap();

    temp_env::with_vars(
        [("SECRETENV_HOME", Some(tmp.path().to_str().unwrap()))],
        || {
            let result = resolve_workspace_from_config().unwrap();
            assert_eq!(
                result,
                Some(PathBuf::from("/tmp/test-workspace/.secretenv"))
            );
        },
    );
}

#[test]
fn expands_tilde_in_workspace_path() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "HOME"]);
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");
    fs::write(
        &config_path,
        "format = \"secretenv/config@1\"\nworkspace = \"~/projects/.secretenv\"\n",
    )
    .unwrap();

    temp_env::with_vars(
        [("SECRETENV_HOME", Some(tmp.path().to_str().unwrap()))],
        || {
            let result = resolve_workspace_from_config().unwrap();
            let home = std::env::var("HOME").unwrap();
            assert_eq!(
                result,
                Some(PathBuf::from(format!("{}/projects/.secretenv", home)))
            );
        },
    );
}
