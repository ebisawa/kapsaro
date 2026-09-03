// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests CLI-owned environment and configuration input resolution.
//! Covers precedence and conditional SSH agent socket discovery.

use std::env;
use std::path::PathBuf;

use crate::cli::options::CommonOptions;
use crate::test_utils::EnvGuard;
use kapsaro_test_support::fixture::{local_state_temp_dir, write_local_state_file};
use serial_test::serial;

use super::CliContext;

fn build_context(home: &std::path::Path) -> CliContext {
    CliContext::resolve(&CommonOptions {
        home: Some(home.to_path_buf()),
        ..CommonOptions::default()
    })
    .expect("CLI context should resolve")
}

fn save_github_user_config(home: &std::path::Path, github_user: &str) {
    write_local_state_file(
        &home.join("config.toml"),
        format!("github_user = \"{github_user}\"\n"),
    );
}

fn save_invalid_identity_agent_config(home: &std::path::Path) {
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(
        ssh_dir.join("config"),
        "Host *\n    IdentityAgent ${KAPSARO_UNDEFINED_IDENTITY_AGENT_TEST}/agent.sock\n",
    )
    .unwrap();
}

fn build_ssh_keygen_context(home: &std::path::Path, identity: PathBuf) -> CliContext {
    CliContext::resolve(&CommonOptions {
        home: Some(home.to_path_buf()),
        identity: Some(identity),
        ssh_keygen: true,
        ..CommonOptions::default()
    })
    .expect("CLI context should resolve")
}

#[test]
#[serial]
fn test_github_user_invalid_cli_value_error() {
    let _guard = EnvGuard::new(&["KAPSARO_GITHUB_USER"]);
    let home = local_state_temp_dir();
    env::remove_var("KAPSARO_GITHUB_USER");

    let result = build_context(home.path()).github_user(Some("alice/keys".to_string()));

    assert!(result.is_err());
}

#[test]
#[serial]
fn test_github_user_invalid_environment_value_error() {
    let _guard = EnvGuard::new(&["KAPSARO_GITHUB_USER"]);
    let home = local_state_temp_dir();
    env::set_var("KAPSARO_GITHUB_USER", "alice?tab=keys");

    let result = build_context(home.path()).github_user(None);

    assert!(result.is_err());
}

#[test]
#[serial]
fn test_github_user_invalid_config_value_error() {
    let _guard = EnvGuard::new(&["KAPSARO_GITHUB_USER"]);
    let home = local_state_temp_dir();
    env::remove_var("KAPSARO_GITHUB_USER");
    save_github_user_config(home.path(), "alice#keys");

    let result = build_context(home.path()).github_user(None);

    assert!(result.is_err());
}

#[test]
#[serial]
fn test_github_user_cli_value_precedes_invalid_lower_priority_values() {
    let _guard = EnvGuard::new(&["KAPSARO_GITHUB_USER"]);
    let home = local_state_temp_dir();
    env::set_var("KAPSARO_GITHUB_USER", "alice?tab=keys");
    save_github_user_config(home.path(), "alice#keys");

    let result = build_context(home.path())
        .github_user(Some("cli-user".to_string()))
        .expect("valid CLI value should take precedence");

    assert_eq!(result.as_deref(), Some("cli-user"));
}

#[test]
#[serial]
fn test_github_user_environment_value_precedes_invalid_config_value() {
    let _guard = EnvGuard::new(&["KAPSARO_GITHUB_USER"]);
    let home = local_state_temp_dir();
    env::set_var("KAPSARO_GITHUB_USER", "env-user");
    save_github_user_config(home.path(), "alice#keys");

    let result = build_context(home.path())
        .github_user(None)
        .expect("valid environment value should take precedence");

    assert_eq!(result.as_deref(), Some("env-user"));
}

#[test]
#[serial]
fn test_member_handle_cli_value_precedes_invalid_config_file() {
    let _guard = EnvGuard::new(&["KAPSARO_MEMBER_HANDLE"]);
    let home = local_state_temp_dir();
    env::remove_var("KAPSARO_MEMBER_HANDLE");
    write_local_state_file(&home.path().join("config.toml"), "member_handle = [\n");

    let result = build_context(home.path())
        .member_handle(Some("alice@example.com".to_string()))
        .expect("CLI member handle must avoid unrelated config parsing");

    assert_eq!(result.as_deref(), Some("alice@example.com"));
}

#[test]
#[serial]
fn test_member_handle_environment_value_precedes_invalid_config_file() {
    let _guard = EnvGuard::new(&["KAPSARO_MEMBER_HANDLE"]);
    let home = local_state_temp_dir();
    env::set_var("KAPSARO_MEMBER_HANDLE", "alice@example.com");
    write_local_state_file(&home.path().join("config.toml"), "member_handle = [\n");

    let result = build_context(home.path())
        .member_handle(None)
        .expect("environment member handle must avoid unrelated config parsing");

    assert_eq!(result.as_deref(), Some("alice@example.com"));
}

#[test]
#[serial]
fn test_optional_local_state_caches_missing_home() {
    let _guard = EnvGuard::new(&["HOME", "KAPSARO_HOME"]);
    env::remove_var("HOME");
    env::remove_var("KAPSARO_HOME");
    let context = CliContext::resolve(&CommonOptions::default()).unwrap();

    assert!(context.optional_local_state().unwrap().is_none());

    env::set_var("HOME", PathBuf::from("/must/not/be/re_resolved"));
    assert!(context.optional_local_state().unwrap().is_none());
}

#[test]
#[serial]
fn test_explicit_workspace_resolution_does_not_require_home() {
    let _guard = EnvGuard::new(&["HOME", "KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let workspace = tempfile::TempDir::new().unwrap();
    env::remove_var("HOME");
    env::remove_var("KAPSARO_HOME");
    env::remove_var("KAPSARO_WORKSPACE");
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    std::fs::create_dir(workspace.path().join("secrets")).unwrap();
    let context = CliContext::resolve(&CommonOptions {
        workspace: Some(workspace.path().to_path_buf()),
        ..CommonOptions::default()
    })
    .unwrap();

    assert_eq!(
        context.workspace_path().unwrap(),
        workspace.path().canonicalize().unwrap()
    );
}

#[test]
#[serial]
fn test_ssh_keygen_private_identity_skips_invalid_identity_agent() {
    let _guard = EnvGuard::new(&[
        "HOME",
        "SSH_AUTH_SOCK",
        "KAPSARO_UNDEFINED_IDENTITY_AGENT_TEST",
    ]);
    let home = local_state_temp_dir();
    env::set_var("HOME", home.path());
    env::remove_var("SSH_AUTH_SOCK");
    env::remove_var("KAPSARO_UNDEFINED_IDENTITY_AGENT_TEST");
    save_invalid_identity_agent_config(home.path());
    let context = build_ssh_keygen_context(home.path(), home.path().join("id_ed25519"));

    context
        .ssh_signing_inputs()
        .expect("private identity should not require SSH agent socket resolution");
}

#[test]
#[serial]
fn test_ssh_keygen_public_identity_invalid_identity_agent_error() {
    let _guard = EnvGuard::new(&[
        "HOME",
        "SSH_AUTH_SOCK",
        "KAPSARO_UNDEFINED_IDENTITY_AGENT_TEST",
    ]);
    let home = local_state_temp_dir();
    env::set_var("HOME", home.path());
    env::remove_var("SSH_AUTH_SOCK");
    env::remove_var("KAPSARO_UNDEFINED_IDENTITY_AGENT_TEST");
    save_invalid_identity_agent_config(home.path());
    let context = build_ssh_keygen_context(home.path(), home.path().join("id_ed25519.pub"));

    let error = context
        .ssh_signing_inputs()
        .expect_err("public identity should require SSH agent socket resolution");

    assert!(
        error
            .to_string()
            .contains("KAPSARO_UNDEFINED_IDENTITY_AGENT_TEST"),
        "{error}"
    );
}
