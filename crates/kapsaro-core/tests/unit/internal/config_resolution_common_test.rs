// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::config::resolution::common::{
    expand_tilde, resolve_ssh_add_path, resolve_ssh_keygen_path,
};
use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::test_utils::{local_state_temp_dir, write_local_state_file, EnvGuard};
use serial_test::serial;
use std::env;
use std::path::PathBuf;

#[test]
#[serial]
fn test_expand_tilde_with_slash() {
    let _guard = EnvGuard::new(&["HOME"]);
    env::set_var("HOME", "/home/testuser");
    let result = expand_tilde("~/.ssh/id_ed25519").unwrap();
    assert_eq!(result, PathBuf::from("/home/testuser/.ssh/id_ed25519"));
}

#[test]
#[serial]
fn test_expand_tilde_alone() {
    let _guard = EnvGuard::new(&["HOME"]);
    env::set_var("HOME", "/home/testuser");
    let result = expand_tilde("~").unwrap();
    assert_eq!(result, PathBuf::from("/home/testuser"));
}

#[test]
fn test_expand_tilde_no_tilde() {
    let result = expand_tilde("/absolute/path").unwrap();
    assert_eq!(result, PathBuf::from("/absolute/path"));
}

#[test]
fn test_resolve_ssh_keygen_path_from_new_config_key() {
    let temp = local_state_temp_dir();
    let config_path = temp.path().join("config.toml");
    write_local_state_file(
        &config_path,
        "ssh_keygen_command = \"/custom/ssh-keygen\"\n",
    );

    let config = GlobalConfigSnapshot::for_base_dir(Some(temp.path()));
    let result = resolve_ssh_keygen_path(&config).unwrap();

    assert_eq!(result, "/custom/ssh-keygen");
}

#[test]
fn test_resolve_ssh_add_path_from_new_config_key() {
    let temp = local_state_temp_dir();
    let config_path = temp.path().join("config.toml");
    write_local_state_file(&config_path, "ssh_add_command = \"/custom/ssh-add\"\n");

    let config = GlobalConfigSnapshot::for_base_dir(Some(temp.path()));
    let result = resolve_ssh_add_path(&config).unwrap();

    assert_eq!(result, "/custom/ssh-add");
}

#[test]
#[serial]
fn test_resolve_string_required_uses_default_when_unset() {
    let _guard = EnvGuard::new(&["KAPSARO_TEST_STRING"]);
    env::remove_var("KAPSARO_TEST_STRING");
    let temp = local_state_temp_dir();

    let config = GlobalConfigSnapshot::for_base_dir(Some(temp.path()));
    let result = super::resolve_string_required(
        None,
        Some("KAPSARO_TEST_STRING"),
        "test_value",
        &config,
        "fallback".to_string(),
    )
    .unwrap();

    assert_eq!(result, "fallback");
}

#[test]
#[serial]
fn test_resolve_string_with_priority_prefers_env_over_config() {
    let _guard = EnvGuard::new(&["KAPSARO_TEST_STRING"]);
    let temp = local_state_temp_dir();
    let config_path = temp.path().join("config.toml");
    write_local_state_file(&config_path, "test_value = \"from-config\"\n");
    env::set_var("KAPSARO_TEST_STRING", "from-env");

    let config = GlobalConfigSnapshot::for_base_dir(Some(temp.path()));
    let result = super::resolve_string_with_priority(
        None,
        Some("KAPSARO_TEST_STRING"),
        "test_value",
        &config,
        Some("fallback".to_string()),
    )
    .unwrap();

    assert_eq!(result, Some("from-env".to_string()));
}

/// A snapshot answers every key from the one reading it took, so two settings
/// resolved through it agree with what the file holds.
#[test]
fn test_one_snapshot_answers_every_configured_key() {
    let temp = local_state_temp_dir();
    write_local_state_file(
        &temp.path().join("config.toml"),
        "ssh_keygen_command = \"/custom/ssh-keygen\"\nssh_add_command = \"/custom/ssh-add\"\n",
    );

    let config = GlobalConfigSnapshot::for_base_dir(Some(temp.path()));

    assert_eq!(
        resolve_ssh_keygen_path(&config).unwrap(),
        "/custom/ssh-keygen"
    );
    assert_eq!(resolve_ssh_add_path(&config).unwrap(), "/custom/ssh-add");
}
