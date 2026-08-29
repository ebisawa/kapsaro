// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::test_utils::{local_state_temp_dir, with_temp_cwd, write_local_state_file, EnvGuard};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn returns_none_when_no_workspace_in_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "HOME"]);
    let tmp = local_state_temp_dir();
    let config_path = tmp.path().join("config.toml");
    write_local_state_file(&config_path, "member_handle = \"alice\"\n");
    std::env::set_var("KAPSARO_HOME", tmp.path());

    let config = GlobalConfigSnapshot::for_base_dir(None);
    let result = resolve_workspace_from_config_base(&config).unwrap();
    assert!(result.is_none());
}

#[test]
fn returns_path_when_workspace_in_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "HOME"]);
    let tmp = local_state_temp_dir();
    let config_path = tmp.path().join("config.toml");
    write_local_state_file(
        &config_path,
        "workspace = \"/tmp/test-workspace/.kapsaro\"\n",
    );
    std::env::set_var("KAPSARO_HOME", tmp.path());

    let config = GlobalConfigSnapshot::for_base_dir(None);
    let result = resolve_workspace_from_config_base(&config).unwrap();
    assert_eq!(result, Some(PathBuf::from("/tmp/test-workspace/.kapsaro")));
}

#[test]
fn expands_tilde_in_workspace_path() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "HOME"]);
    let tmp = local_state_temp_dir();
    let config_path = tmp.path().join("config.toml");
    write_local_state_file(&config_path, "workspace = \"~/projects/.kapsaro\"\n");
    std::env::set_var("KAPSARO_HOME", tmp.path());

    let config = GlobalConfigSnapshot::for_base_dir(None);
    let result = resolve_workspace_from_config_base(&config).unwrap();
    let home = std::env::var("HOME").unwrap();
    assert_eq!(
        result,
        Some(PathBuf::from(format!("{}/projects/.kapsaro", home)))
    );
}

#[test]
fn cli_workspace_takes_priority_over_env_and_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let cli_dir = tempfile::tempdir().unwrap();
    let env_dir = tempfile::tempdir().unwrap();
    let config_workspace_dir = tempfile::tempdir().unwrap();
    let cli_workspace = build_workspace(cli_dir.path());
    let env_workspace = build_workspace(env_dir.path());
    let config_workspace = build_workspace(config_workspace_dir.path());
    let config_dir = local_state_temp_dir();
    write_local_state_file(
        &config_dir.path().join("config.toml"),
        format!("workspace = \"{}\"\n", config_workspace.display()),
    );
    std::env::set_var("KAPSARO_HOME", config_dir.path());
    std::env::set_var("KAPSARO_WORKSPACE", &env_workspace);

    let config = GlobalConfigSnapshot::for_base_dir(Some(config_dir.path()));
    let resolution = resolve_optional_workspace_from_sources(Some(cli_workspace.clone()), &config)
        .unwrap()
        .unwrap();
    assert_eq!(resolution.root.root_path, cli_workspace);
    assert_eq!(resolution.source, WorkspaceSource::CommandLine);
}

#[test]
fn env_workspace_takes_priority_over_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let env_dir = tempfile::tempdir().unwrap();
    let config_workspace_dir = tempfile::tempdir().unwrap();
    let env_workspace = build_workspace(env_dir.path());
    let config_workspace = build_workspace(config_workspace_dir.path());
    let config_dir = local_state_temp_dir();
    write_local_state_file(
        &config_dir.path().join("config.toml"),
        format!("workspace = \"{}\"\n", config_workspace.display()),
    );
    std::env::set_var("KAPSARO_HOME", config_dir.path());
    std::env::set_var("KAPSARO_WORKSPACE", &env_workspace);

    let config = GlobalConfigSnapshot::for_base_dir(Some(config_dir.path()));
    let resolution = resolve_optional_workspace_from_sources(None, &config)
        .unwrap()
        .unwrap();
    assert_eq!(resolution.root.root_path, env_workspace);
    assert_eq!(resolution.source, WorkspaceSource::Environment);
}

#[test]
fn config_workspace_takes_priority_over_auto_detect() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let config_workspace_dir = tempfile::tempdir().unwrap();
    let config_workspace = build_workspace(config_workspace_dir.path());
    let auto_workspace_dir = tempfile::tempdir().unwrap();
    let auto_workspace = build_workspace(auto_workspace_dir.path());
    let config_dir = local_state_temp_dir();
    write_local_state_file(
        &config_dir.path().join("config.toml"),
        format!("workspace = \"{}\"\n", config_workspace.display()),
    );
    std::env::set_var("KAPSARO_HOME", config_dir.path());
    std::env::remove_var("KAPSARO_WORKSPACE");

    let config = GlobalConfigSnapshot::for_base_dir(Some(config_dir.path()));
    let resolution = with_temp_cwd(auto_workspace_dir.path(), || {
        resolve_optional_workspace_from_sources(None, &config)
            .unwrap()
            .unwrap()
    });

    assert_eq!(resolution.root.root_path, config_workspace);
    assert_ne!(resolution.root.root_path, auto_workspace);
    assert_eq!(resolution.source, WorkspaceSource::GlobalConfig);
}

#[test]
fn workspace_local_config_is_ignored_by_auto_detect() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let current_dir = tempfile::tempdir().unwrap();
    let current_workspace = build_workspace(current_dir.path());
    let other_workspace_dir = tempfile::tempdir().unwrap();
    let other_workspace = build_workspace(other_workspace_dir.path());
    fs::write(
        current_workspace.join("config.toml"),
        format!("workspace = \"{}\"\n", other_workspace.display()),
    )
    .unwrap();
    let empty_home = local_state_temp_dir();
    std::env::set_var("KAPSARO_HOME", empty_home.path());
    std::env::remove_var("KAPSARO_WORKSPACE");

    let config = GlobalConfigSnapshot::for_base_dir(Some(empty_home.path()));
    let resolution = with_temp_cwd(current_dir.path(), || {
        resolve_optional_workspace_from_sources(None, &config)
            .unwrap()
            .unwrap()
    });

    assert_eq!(resolution.root.root_path, current_workspace);
    assert_eq!(resolution.source, WorkspaceSource::AutoDetect);
}

fn build_workspace(root: &Path) -> PathBuf {
    let workspace = root.join(".kapsaro");
    fs::create_dir_all(workspace.join("members/active")).unwrap();
    fs::create_dir_all(workspace.join("members/incoming")).unwrap();
    fs::create_dir_all(workspace.join("secrets")).unwrap();
    workspace.canonicalize().unwrap()
}
