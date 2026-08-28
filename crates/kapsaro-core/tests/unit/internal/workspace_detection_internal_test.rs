// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::load_optional_workspace;
use crate::test_utils::{local_state_temp_dir, with_temp_cwd, write_local_state_file, EnvGuard};

use super::resolution::resolve_optional_workspace;
use super::*;
use std::fs;

#[test]
fn app_context_resolves_workspace_from_config_toml() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join(".kapsaro");
    fs::create_dir_all(ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(ws_path.join("secrets")).unwrap();

    let config_dir = local_state_temp_dir();
    let config_content = format!("workspace = \"{}\"\n", ws_path.display());
    write_local_state_file(&config_dir.path().join("config.toml"), &config_content);
    std::env::set_var("KAPSARO_HOME", config_dir.path());
    std::env::remove_var("KAPSARO_WORKSPACE");

    let options = command_options(Some(config_dir.path().to_path_buf()), None);
    let result = load_optional_workspace(&options).unwrap().unwrap();
    assert_eq!(result.root_path, ws_path.canonicalize().unwrap());
}

#[test]
fn app_context_resolves_workspace_from_options_home_config_without_kapsaro_home() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join(".kapsaro");
    fs::create_dir_all(ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(ws_path.join("secrets")).unwrap();

    let config_dir = local_state_temp_dir();
    let config_content = format!("workspace = \"{}\"\n", ws_path.display());
    write_local_state_file(&config_dir.path().join("config.toml"), &config_content);
    std::env::remove_var("KAPSARO_HOME");
    std::env::remove_var("KAPSARO_WORKSPACE");

    let cwd = tempfile::tempdir().unwrap();
    let result = with_temp_cwd(cwd.path(), || {
        let options = command_options(Some(config_dir.path().to_path_buf()), None);
        load_optional_workspace(&options).unwrap().unwrap()
    });

    assert_eq!(result.root_path, ws_path.canonicalize().unwrap());
}

#[test]
fn app_context_config_invalid_path_shows_config_source() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let config_dir = local_state_temp_dir();
    let config_content = "workspace = \"/nonexistent/path/.kapsaro\"\n";
    write_local_state_file(&config_dir.path().join("config.toml"), config_content);
    std::env::set_var("KAPSARO_HOME", config_dir.path());
    std::env::remove_var("KAPSARO_WORKSPACE");

    let options = command_options(Some(config_dir.path().to_path_buf()), None);
    let result = load_optional_workspace(&options);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("config.toml"),
        "Error should mention config.toml: {}",
        err_msg
    );
}

#[test]
fn app_context_env_var_takes_priority_over_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let env_ws = tempfile::tempdir().unwrap();
    let env_ws_path = env_ws.path().join(".kapsaro");
    fs::create_dir_all(env_ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(env_ws_path.join("secrets")).unwrap();

    let config_ws = tempfile::tempdir().unwrap();
    let config_ws_path = config_ws.path().join(".kapsaro");
    fs::create_dir_all(config_ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(config_ws_path.join("secrets")).unwrap();

    let config_dir = local_state_temp_dir();
    let config_content = format!("workspace = \"{}\"\n", config_ws_path.display());
    write_local_state_file(&config_dir.path().join("config.toml"), &config_content);
    std::env::set_var("KAPSARO_HOME", config_dir.path());
    std::env::set_var("KAPSARO_WORKSPACE", &env_ws_path);

    let options = command_options(Some(config_dir.path().to_path_buf()), None);
    let result = load_optional_workspace(&options).unwrap().unwrap();
    assert_eq!(result.root_path, env_ws_path.canonicalize().unwrap());
}

#[test]
fn app_context_explicit_option_takes_priority_over_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let explicit_ws = tempfile::tempdir().unwrap();
    let explicit_ws_path = explicit_ws.path().join(".kapsaro");
    fs::create_dir_all(explicit_ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(explicit_ws_path.join("secrets")).unwrap();

    let config_ws = tempfile::tempdir().unwrap();
    let config_ws_path = config_ws.path().join(".kapsaro");
    fs::create_dir_all(config_ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(config_ws_path.join("secrets")).unwrap();

    let config_dir = local_state_temp_dir();
    let config_content = format!("workspace = \"{}\"\n", config_ws_path.display());
    write_local_state_file(&config_dir.path().join("config.toml"), &config_content);
    std::env::set_var("KAPSARO_HOME", config_dir.path());
    std::env::remove_var("KAPSARO_WORKSPACE");

    let options = command_options(
        Some(config_dir.path().to_path_buf()),
        Some(explicit_ws_path.clone()),
    );
    let result = load_optional_workspace(&options).unwrap().unwrap();
    assert_eq!(result.root_path, explicit_ws_path.canonicalize().unwrap());
}

#[test]
fn app_context_explicit_option_resolves_without_home() {
    let _guard = EnvGuard::new(&["HOME", "KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let explicit_ws = tempfile::tempdir().unwrap();
    let explicit_ws_path = explicit_ws.path().join(".kapsaro");
    fs::create_dir_all(explicit_ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(explicit_ws_path.join("secrets")).unwrap();

    std::env::remove_var("HOME");
    std::env::remove_var("KAPSARO_HOME");
    std::env::remove_var("KAPSARO_WORKSPACE");

    let options = command_options(None, Some(explicit_ws_path.clone()));
    let result = load_optional_workspace(&options).unwrap().unwrap();

    assert_eq!(result.root_path, explicit_ws_path.canonicalize().unwrap());
}

#[test]
fn app_context_env_workspace_resolves_without_home() {
    let _guard = EnvGuard::new(&["HOME", "KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let env_ws = tempfile::tempdir().unwrap();
    let env_ws_path = env_ws.path().join(".kapsaro");
    fs::create_dir_all(env_ws_path.join("members").join("active")).unwrap();
    fs::create_dir_all(env_ws_path.join("secrets")).unwrap();

    std::env::remove_var("HOME");
    std::env::remove_var("KAPSARO_HOME");
    std::env::set_var("KAPSARO_WORKSPACE", env_ws_path.to_str().unwrap());

    let options = command_options(None, None);
    let result = load_optional_workspace(&options).unwrap().unwrap();

    assert_eq!(result.root_path, env_ws_path.canonicalize().unwrap());
}

#[test]
fn resolve_optional_workspace_returns_none_when_nothing_is_configured() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let temp_dir = tempfile::tempdir().unwrap();
    std::env::remove_var("KAPSARO_HOME");
    std::env::remove_var("KAPSARO_WORKSPACE");

    let result = with_temp_cwd(temp_dir.path(), || {
        resolve_optional_workspace(None).unwrap()
    });

    assert!(result.is_none());
}

#[test]
fn resolve_workspace_detects_current_dot_kapsaro_without_git() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let temp_dir = tempfile::tempdir().unwrap();
    let workspace_path = temp_dir.path().join(".kapsaro");
    fs::create_dir_all(workspace_path.join("members/active")).unwrap();
    fs::create_dir_all(workspace_path.join("secrets")).unwrap();
    std::env::remove_var("KAPSARO_HOME");
    std::env::remove_var("KAPSARO_WORKSPACE");

    let result = with_temp_cwd(temp_dir.path(), || resolve_workspace(None).unwrap());

    assert_eq!(result.root_path, workspace_path.canonicalize().unwrap());
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
    CommonCommandOptions::new()
        .with_home(home)
        .with_workspace(workspace)
}
