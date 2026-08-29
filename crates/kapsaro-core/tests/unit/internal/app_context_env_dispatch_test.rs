// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for read/write execution context resolution behavior.
//!
//! Verifies that read/write resolution correctly dispatches to
//! environment variable key loading when ssh_ctx is None, and handles
//! workspace / env var requirements.

use crate::app::context::execution::{resolve_read_execution, ExecutionContext};
use crate::app::context::member::{
    resolve_key_owner_with_access, resolve_required_member_with_optional_access,
};
use crate::app::context::paths::CommandPathResolution;
use crate::app_test_utils::build_test_command_options;
use crate::io::keystore::access::KeystoreAccess;
use crate::test_utils::{setup_test_keystore, EnvGuard};
use tempfile::TempDir;

const ENV_PRIVATE_KEY: &str = "KAPSARO_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "KAPSARO_KEY_PASSWORD";
const ENV_WORKSPACE: &str = "KAPSARO_WORKSPACE";
const ENV_HOME: &str = "KAPSARO_HOME";

fn ensure_workspace_dirs(path: &std::path::Path) {
    std::fs::create_dir_all(path.join("members/active")).unwrap();
    std::fs::create_dir_all(path.join("members/incoming")).unwrap();
    std::fs::create_dir_all(path.join("secrets")).unwrap();
}

fn expect_err(result: kapsaro_core::Result<ExecutionContext>) -> String {
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

    let err = expect_err(resolve_read_execution(&options, None, None));
    assert!(
        err.contains("not a valid workspace"),
        "Expected workspace validation error, got: {}",
        err
    );
}

#[test]
fn test_load_from_env_without_env_var_fails() {
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

    // The env branch is taken from the mode, so reaching this state through
    // `resolve_read_execution` is not possible; the loader itself is what has to
    // name the missing variable.
    let err = expect_err(ExecutionContext::load_from_env(&options));
    assert!(
        err.contains("not set"),
        "Expected 'not set' error for missing KAPSARO_PRIVATE_KEY, got: {}",
        err
    );
}

#[test]
fn test_resolve_read_execution_rejects_member_handle_in_env_mode() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();

    let options = build_test_command_options(home.path(), None);

    // Environment key mode takes the branch, so a member handle is rejected.
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(resolve_read_execution(
        &options,
        Some("alice@example.com".to_string()),
        None,
    ));
    assert!(
        err.contains("--member-handle cannot be used"),
        "Expected --member-handle rejection error, got: {}",
        err
    );
}

#[test]
fn test_resolve_read_execution_rejects_kid_in_env_mode() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD, ENV_WORKSPACE, ENV_HOME]);
    std::env::remove_var(ENV_WORKSPACE);

    let home = TempDir::new().unwrap();

    let options = build_test_command_options(home.path(), None);

    // Environment key mode takes the branch, so an explicit kid is rejected.
    std::env::set_var(ENV_PRIVATE_KEY, "dummy");
    std::env::set_var(ENV_KEY_PASSWORD, "dummy");

    let err = expect_err(resolve_read_execution(
        &options,
        None,
        Some("01HTEST00000000000000ALICE"),
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
    ensure_workspace_dirs(workspace.path());
    let options = build_test_command_options(home.path(), Some(workspace.path()));

    let resolved = CommandPathResolution::load(&options).unwrap();

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
fn test_resolve_required_member_uses_config_resolution_member_handle() {
    let home = crate::test_utils::local_state_temp_dir();
    crate::test_utils::write_local_state_file(
        &home.path().join("config.toml"),
        "member_handle = 'alice@example.com'\n",
    );
    let opened_home = crate::support::fs::anchor::AnchoredDir::open(
        home.path(),
        crate::support::fs::relative::DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap();

    let resolved =
        resolve_required_member_with_optional_access(Some(&opened_home), None, None).unwrap();

    assert_eq!(resolved.as_str(), "alice@example.com");
}

#[test]
fn test_resolve_key_owner_uses_kid_lookup_when_member_handle_missing() {
    let home = setup_test_keystore("alice@example.com");
    let options = build_test_command_options(home.path(), None);
    let key_ctx = kapsaro_core::cli_api::test_support::storage::keystore::active::load_active_kid(
        "alice@example.com",
        &home.path().join("keys"),
    )
    .unwrap()
    .unwrap();

    let paths = CommandPathResolution::load(&options).unwrap();
    let access = KeystoreAccess::open_from_home(&paths.base_dir).unwrap();

    let resolved = resolve_key_owner_with_access(&access, None, &key_ctx).unwrap();

    assert_eq!(resolved.as_str(), "alice@example.com");
}

#[test]
fn test_resolve_key_owner_uses_kid_prefix_lookup_when_member_handle_missing() {
    let home = setup_test_keystore("alice@example.com");
    let options = build_test_command_options(home.path(), None);
    let key_ctx = kapsaro_core::cli_api::test_support::storage::keystore::active::load_active_kid(
        "alice@example.com",
        &home.path().join("keys"),
    )
    .unwrap()
    .unwrap();

    let paths = CommandPathResolution::load(&options).unwrap();
    let access = KeystoreAccess::open_from_home(&paths.base_dir).unwrap();

    let resolved = resolve_key_owner_with_access(&access, None, &key_ctx[..4]).unwrap();

    assert_eq!(resolved.as_str(), "alice@example.com");
}

/// A handle the caller named is the owner it names, whichever key the kid
/// stands for. The keystore search is the fallback for a command that named no
/// handle, so a kid no key answers to never has to resolve here.
#[test]
fn test_resolve_key_owner_keeps_an_explicitly_named_member_handle() {
    let home = setup_test_keystore("alice@example.com");
    let options = build_test_command_options(home.path(), None);
    let paths = CommandPathResolution::load(&options).unwrap();
    let access = KeystoreAccess::open_from_home(&paths.base_dir).unwrap();

    let resolved = resolve_key_owner_with_access(
        &access,
        Some("alice@example.com".to_string()),
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
    )
    .unwrap();

    assert_eq!(resolved.as_str(), "alice@example.com");
}
