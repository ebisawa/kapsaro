// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::EnvGuard;
use std::fs;
use std::path::{Path, PathBuf};

use serial_test::serial;

#[test]
fn returns_none_when_no_workspace_in_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "HOME"]);
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");
    fs::write(&config_path, "member_handle = \"alice\"\n").unwrap();

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
        "workspace = \"/tmp/test-workspace/.secretenv\"\n",
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
    fs::write(&config_path, "workspace = \"~/projects/.secretenv\"\n").unwrap();

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

#[test]
fn cli_workspace_takes_priority_over_env_and_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_WORKSPACE"]);
    let cli_dir = tempfile::tempdir().unwrap();
    let env_dir = tempfile::tempdir().unwrap();
    let config_workspace_dir = tempfile::tempdir().unwrap();
    let cli_workspace = build_workspace(cli_dir.path());
    let env_workspace = build_workspace(env_dir.path());
    let config_workspace = build_workspace(config_workspace_dir.path());
    let config_dir = tempfile::tempdir().unwrap();
    fs::write(
        config_dir.path().join("config.toml"),
        format!("workspace = \"{}\"\n", config_workspace.display()),
    )
    .unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(config_dir.path().to_str().unwrap())),
            ("SECRETENV_WORKSPACE", Some(env_workspace.to_str().unwrap())),
        ],
        || {
            let resolution = resolve_optional_workspace_from_sources(
                Some(cli_workspace.clone()),
                Some(config_dir.path()),
            )
            .unwrap()
            .unwrap();
            assert_eq!(resolution.root.root_path, cli_workspace);
            assert_eq!(resolution.source, WorkspaceSource::CommandLine);
        },
    );
}

#[test]
fn env_workspace_takes_priority_over_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_WORKSPACE"]);
    let env_dir = tempfile::tempdir().unwrap();
    let config_workspace_dir = tempfile::tempdir().unwrap();
    let env_workspace = build_workspace(env_dir.path());
    let config_workspace = build_workspace(config_workspace_dir.path());
    let config_dir = tempfile::tempdir().unwrap();
    fs::write(
        config_dir.path().join("config.toml"),
        format!("workspace = \"{}\"\n", config_workspace.display()),
    )
    .unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(config_dir.path().to_str().unwrap())),
            ("SECRETENV_WORKSPACE", Some(env_workspace.to_str().unwrap())),
        ],
        || {
            let resolution = resolve_optional_workspace_from_sources(None, Some(config_dir.path()))
                .unwrap()
                .unwrap();
            assert_eq!(resolution.root.root_path, env_workspace);
            assert_eq!(resolution.source, WorkspaceSource::Environment);
        },
    );
}

#[test]
#[serial]
fn config_workspace_takes_priority_over_auto_detect() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_WORKSPACE"]);
    let config_workspace_dir = tempfile::tempdir().unwrap();
    let config_workspace = build_workspace(config_workspace_dir.path());
    let auto_workspace_dir = tempfile::tempdir().unwrap();
    let auto_workspace = build_workspace(auto_workspace_dir.path());
    let config_dir = tempfile::tempdir().unwrap();
    fs::write(
        config_dir.path().join("config.toml"),
        format!("workspace = \"{}\"\n", config_workspace.display()),
    )
    .unwrap();

    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(auto_workspace_dir.path()).unwrap();
    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(config_dir.path().to_str().unwrap())),
            ("SECRETENV_WORKSPACE", None::<&str>),
        ],
        || {
            let resolution = resolve_optional_workspace_from_sources(None, Some(config_dir.path()))
                .unwrap()
                .unwrap();
            assert_eq!(resolution.root.root_path, config_workspace);
            assert_ne!(resolution.root.root_path, auto_workspace);
            assert_eq!(resolution.source, WorkspaceSource::GlobalConfig);
        },
    );
    std::env::set_current_dir(original_dir).unwrap();
}

#[test]
#[serial]
fn workspace_local_config_is_ignored_by_auto_detect() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_WORKSPACE"]);
    let current_dir = tempfile::tempdir().unwrap();
    let current_workspace = build_workspace(current_dir.path());
    let other_workspace_dir = tempfile::tempdir().unwrap();
    let other_workspace = build_workspace(other_workspace_dir.path());
    fs::write(
        current_workspace.join("config.toml"),
        format!("workspace = \"{}\"\n", other_workspace.display()),
    )
    .unwrap();
    let empty_home = tempfile::tempdir().unwrap();

    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(current_dir.path()).unwrap();
    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(empty_home.path().to_str().unwrap())),
            ("SECRETENV_WORKSPACE", None::<&str>),
        ],
        || {
            let resolution = resolve_optional_workspace_from_sources(None, Some(empty_home.path()))
                .unwrap()
                .unwrap();
            assert_eq!(resolution.root.root_path, current_workspace);
            assert_eq!(resolution.source, WorkspaceSource::AutoDetect);
        },
    );
    std::env::set_current_dir(original_dir).unwrap();
}

#[test]
#[serial]
fn auto_detect_failure_adds_workspace_resolution_guidance() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_WORKSPACE"]);
    let current_dir = tempfile::tempdir().unwrap();
    let empty_home = tempfile::tempdir().unwrap();

    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(current_dir.path()).unwrap();
    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(empty_home.path().to_str().unwrap())),
            ("SECRETENV_WORKSPACE", None::<&str>),
        ],
        || {
            let error = resolve_workspace_from_sources(None, Some(empty_home.path())).unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains("--workspace") && message.contains("SECRETENV_WORKSPACE"),
                "auto-detect errors should add app/config-level guidance: {message}"
            );
        },
    );
    std::env::set_current_dir(original_dir).unwrap();
}

fn build_workspace(root: &Path) -> PathBuf {
    let workspace = root.join(".secretenv");
    fs::create_dir_all(workspace.join("members/active")).unwrap();
    fs::create_dir_all(workspace.join("members/incoming")).unwrap();
    fs::create_dir_all(workspace.join("secrets")).unwrap();
    workspace.canonicalize().unwrap()
}
