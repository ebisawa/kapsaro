// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::load_optional_workspace;

use super::resolution::resolve_optional_workspace;
use super::*;
use serial_test::serial;
use std::fs;

#[test]
fn io_workspace_detection_resolution_does_not_import_config_resolution() {
    let source_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/io/workspace/detection/resolution.rs");
    let source = fs::read_to_string(&source_path).unwrap();
    assert!(
        !source.contains("crate::config::resolution"),
        "{} must not depend on config resolution",
        source_path.display()
    );
}

#[test]
fn app_context_resolves_workspace_from_config_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join(".secretenv");
    fs::create_dir_all(ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(ws_path.join("secrets")).unwrap();

    let config_dir = tempfile::tempdir().unwrap();
    let config_content = format!("workspace = \"{}\"\n", ws_path.display());
    fs::write(config_dir.path().join("config.toml"), &config_content).unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(config_dir.path().to_str().unwrap())),
            ("SECRETENV_WORKSPACE", None::<&str>),
        ],
        || {
            let options = command_options(Some(config_dir.path().to_path_buf()), None);
            let result = load_optional_workspace(&options).unwrap().unwrap();
            assert_eq!(result.root_path, ws_path.canonicalize().unwrap());
        },
    );
}

#[test]
fn app_context_config_invalid_path_shows_config_source() {
    let config_dir = tempfile::tempdir().unwrap();
    let config_content = "workspace = \"/nonexistent/path/.secretenv\"\n";
    fs::write(config_dir.path().join("config.toml"), config_content).unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(config_dir.path().to_str().unwrap())),
            ("SECRETENV_WORKSPACE", None::<&str>),
        ],
        || {
            let options = command_options(Some(config_dir.path().to_path_buf()), None);
            let result = load_optional_workspace(&options);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("config.toml"),
                "Error should mention config.toml: {}",
                err_msg
            );
        },
    );
}

#[test]
fn app_context_env_var_takes_priority_over_config() {
    let env_ws = tempfile::tempdir().unwrap();
    let env_ws_path = env_ws.path().join(".secretenv");
    fs::create_dir_all(env_ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(env_ws_path.join("secrets")).unwrap();

    let config_ws = tempfile::tempdir().unwrap();
    let config_ws_path = config_ws.path().join(".secretenv");
    fs::create_dir_all(config_ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(config_ws_path.join("secrets")).unwrap();

    let config_dir = tempfile::tempdir().unwrap();
    let config_content = format!("workspace = \"{}\"\n", config_ws_path.display());
    fs::write(config_dir.path().join("config.toml"), &config_content).unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(config_dir.path().to_str().unwrap())),
            ("SECRETENV_WORKSPACE", Some(env_ws_path.to_str().unwrap())),
        ],
        || {
            let options = command_options(Some(config_dir.path().to_path_buf()), None);
            let result = load_optional_workspace(&options).unwrap().unwrap();
            assert_eq!(result.root_path, env_ws_path.canonicalize().unwrap());
        },
    );
}

#[test]
fn app_context_explicit_option_takes_priority_over_config() {
    let explicit_ws = tempfile::tempdir().unwrap();
    let explicit_ws_path = explicit_ws.path().join(".secretenv");
    fs::create_dir_all(explicit_ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(explicit_ws_path.join("secrets")).unwrap();

    let config_ws = tempfile::tempdir().unwrap();
    let config_ws_path = config_ws.path().join(".secretenv");
    fs::create_dir_all(config_ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(config_ws_path.join("secrets")).unwrap();

    let config_dir = tempfile::tempdir().unwrap();
    let config_content = format!("workspace = \"{}\"\n", config_ws_path.display());
    fs::write(config_dir.path().join("config.toml"), &config_content).unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", Some(config_dir.path().to_str().unwrap())),
            ("SECRETENV_WORKSPACE", None::<&str>),
        ],
        || {
            let options = command_options(
                Some(config_dir.path().to_path_buf()),
                Some(explicit_ws_path.clone()),
            );
            let result = load_optional_workspace(&options).unwrap().unwrap();
            assert_eq!(result.root_path, explicit_ws_path.canonicalize().unwrap());
        },
    );
}

#[test]
#[serial]
fn resolve_optional_workspace_returns_none_when_nothing_is_configured() {
    let original_dir = std::env::current_dir().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    std::env::set_current_dir(temp_dir.path()).unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", None::<&str>),
            ("SECRETENV_WORKSPACE", None::<&str>),
        ],
        || {
            let result = resolve_optional_workspace(None).unwrap();
            assert!(result.is_none());
        },
    );

    std::env::set_current_dir(original_dir).unwrap();
}

#[test]
#[serial]
fn resolve_workspace_detects_current_dot_secretenv_without_git() {
    let original_dir = std::env::current_dir().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let workspace_path = temp_dir.path().join(".secretenv");
    fs::create_dir_all(workspace_path.join("members/active")).unwrap();
    fs::create_dir_all(workspace_path.join("secrets")).unwrap();
    std::env::set_current_dir(temp_dir.path()).unwrap();

    temp_env::with_vars(
        [
            ("SECRETENV_HOME", None::<&str>),
            ("SECRETENV_WORKSPACE", None::<&str>),
        ],
        || {
            let result = resolve_workspace(None).unwrap();
            assert_eq!(result.root_path, workspace_path.canonicalize().unwrap());
        },
    );

    std::env::set_current_dir(original_dir).unwrap();
}

#[test]
fn resolve_optional_workspace_preserves_explicit_path_errors() {
    let missing = tempfile::tempdir()
        .unwrap()
        .path()
        .join("missing-workspace");
    let result = resolve_optional_workspace(Some(missing));
    assert!(result.is_err());
}

fn command_options(
    home: Option<std::path::PathBuf>,
    workspace: Option<std::path::PathBuf>,
) -> CommonCommandOptions {
    CommonCommandOptions {
        home,
        identity: None,
        debug: false,
        verbose: false,
        workspace,
        ssh_signing_method: None,
        allow_expired_key: false,
    }
}
