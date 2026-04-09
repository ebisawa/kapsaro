// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for read/write execution context resolution behavior.
//!
//! Verifies that read/write resolution correctly dispatches to
//! environment variable key loading when ssh_ctx is None, and handles
//! workspace / env var requirements.

use crate::app::context::execution::{
    resolve_read_execution, resolve_write_execution, ExecutionContext,
};
use crate::app::context::member::{resolve_key_owner, resolve_required_member};
use crate::app::context::paths::ResolvedCommandPaths;
use crate::app_test_utils::build_test_command_options;
use crate::test_utils::{setup_test_keystore, EnvGuard};
use tempfile::TempDir;

const ENV_PRIVATE_KEY: &str = "SECRETENV_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "SECRETENV_KEY_PASSWORD";
const ENV_WORKSPACE: &str = "SECRETENV_WORKSPACE";
const ENV_HOME: &str = "SECRETENV_HOME";

fn create_workspace_dirs(path: &std::path::Path) {
    std::fs::create_dir_all(path.join("members/active")).unwrap();
    std::fs::create_dir_all(path.join("members/incoming")).unwrap();
    std::fs::create_dir_all(path.join("secrets")).unwrap();
}

fn expect_err(result: secretenv::Result<ExecutionContext>) -> String {
    match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error but got Ok"),
    }
}

#[test]
fn test_resolve_read_execution_requires_workspace_in_env_mode() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();
    let non_workspace = TempDir::new().unwrap();
    let options = build_test_command_options(home.path(), Some(non_workspace.path()));

    // Set env var so load_from_env progresses past key loading,
    // but workspace path lacks required structure — should fail at require_workspace.
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(resolve_read_execution(&options, None, None, None));
    assert!(
        err.contains("not a valid workspace"),
        "Expected workspace validation error, got: {}",
        err
    );
}

#[test]
fn test_resolve_read_execution_without_env_var_fails() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_PRIVATE_KEY);
    std::env::remove_var(ENV_KEY_PASSWORD);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();
    let workspace = TempDir::new().unwrap();
    // Provide a valid workspace directory so require_workspace doesn't fail first.
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace.path().join("secrets")).unwrap();

    let options = build_test_command_options(home.path(), Some(workspace.path()));

    let err = expect_err(resolve_read_execution(&options, None, None, None));
    assert!(
        err.contains("not set"),
        "Expected 'not set' error for missing SECRETENV_PRIVATE_KEY, got: {}",
        err
    );
}

#[test]
fn test_resolve_read_execution_rejects_member_id_in_env_mode() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();

    let options = build_test_command_options(home.path(), None);

    // Provide member_id with ssh_ctx=None to trigger the error path.
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(resolve_read_execution(
        &options,
        Some("alice@example.com".to_string()),
        None,
        None,
    ));
    assert!(
        err.contains("--member-id cannot be used"),
        "Expected --member-id rejection error, got: {}",
        err
    );
}

#[test]
fn test_resolve_read_execution_rejects_kid_in_env_mode() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();

    let options = build_test_command_options(home.path(), None);

    // Provide explicit_kid with ssh_ctx=None to trigger the error path.
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(resolve_read_execution(
        &options,
        None,
        Some("01HTEST00000000000000ALICE"),
        None,
    ));
    assert!(
        err.contains("--kid cannot be used"),
        "Expected --kid rejection error, got: {}",
        err
    );
}

#[test]
fn test_resolved_command_paths_loads_base_dir_and_keystore_root() {
    let home = TempDir::new().unwrap();
    let workspace = TempDir::new().unwrap();
    create_workspace_dirs(workspace.path());
    let options = build_test_command_options(home.path(), Some(workspace.path()));

    let resolved = ResolvedCommandPaths::load(&options).unwrap();

    assert_eq!(resolved.base_dir, home.path());
    assert_eq!(resolved.keystore_root, home.path().join("keys"));
    assert_eq!(
        resolved
            .workspace_root
            .as_ref()
            .map(|w| w.root_path.file_name()),
        Some(workspace.path().file_name())
    );
}

#[test]
fn test_resolve_write_execution_rejects_member_id_in_env_mode() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();

    let options = build_test_command_options(home.path(), None);

    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(resolve_write_execution(
        &options,
        Some("alice@example.com".to_string()),
        None,
    ));
    assert!(
        err.contains("--member-id cannot be used"),
        "Expected --member-id rejection error, got: {}",
        err
    );
}

#[test]
fn test_resolve_required_member_uses_config_resolution_member_id() {
    let home = TempDir::new().unwrap();
    let workspace = TempDir::new().unwrap();
    create_workspace_dirs(workspace.path());
    std::fs::create_dir_all(home.path()).unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        "member_id = 'alice@example.com'\n",
    )
    .unwrap();
    let options = build_test_command_options(home.path(), Some(workspace.path()));

    let resolved = resolve_required_member(&options, None).unwrap();

    assert_eq!(resolved, "alice@example.com");
}

#[test]
fn test_resolve_key_owner_uses_kid_lookup_when_member_id_missing() {
    let home = setup_test_keystore("alice@example.com");
    let options = build_test_command_options(home.path(), None);
    let key_ctx = secretenv::io::keystore::active::load_active_kid(
        "alice@example.com",
        &home.path().join("keys"),
    )
    .unwrap()
    .unwrap();

    let resolved = resolve_key_owner(&options, None, &key_ctx).unwrap();

    assert_eq!(resolved, "alice@example.com");
}
