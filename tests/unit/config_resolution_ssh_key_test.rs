// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::EnvGuard;
use serial_test::serial;
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn create_ssh_key_file(dir: &TempDir, name: &str) -> PathBuf {
    let key_path = dir.path().join(name);
    fs::write(&key_path, "dummy ssh key content").unwrap();
    key_path
}

fn create_global_config_with_ssh_key(temp_home: &TempDir, ssh_key_path: &str) {
    let config_path = temp_home.path().join("config.toml");
    fs::write(&config_path, format!("ssh_key = \"{}\"\n", ssh_key_path)).unwrap();
}

#[test]
#[serial]
fn test_resolve_ssh_key_from_cli_option() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY"]);
    let temp_home = tempfile::tempdir().unwrap();
    let temp_keys = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    let cli_key = create_ssh_key_file(&temp_keys, "cli_key");
    let global_key = create_ssh_key_file(&temp_keys, "global_key");
    create_global_config_with_ssh_key(&temp_home, global_key.to_str().unwrap());

    let result = super::resolve_ssh_key_descriptor(Some(cli_key.clone()), None)
        .map(|descriptor| descriptor.to_path_buf())
        .unwrap();
    assert_eq!(result, cli_key);
}

#[test]
#[serial]
fn test_resolve_ssh_key_from_global_config() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY"]);
    let temp_home = tempfile::tempdir().unwrap();
    let temp_keys = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    let global_key = create_ssh_key_file(&temp_keys, "global_key");
    create_global_config_with_ssh_key(&temp_home, global_key.to_str().unwrap());

    let result = super::resolve_ssh_key_descriptor(None, None)
        .map(|descriptor| descriptor.to_path_buf())
        .unwrap();
    assert_eq!(result, global_key);
}

#[test]
#[serial]
fn test_resolve_ssh_key_from_default_path() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY", "HOME"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    let fake_home = tempfile::tempdir().unwrap();
    let ssh_dir = fake_home.path().join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let default_key = ssh_dir.join("id_ed25519");
    fs::write(&default_key, "dummy default key").unwrap();
    env::set_var("HOME", fake_home.path());

    let result = super::resolve_ssh_key_descriptor(None, None)
        .map(|descriptor| descriptor.to_path_buf())
        .unwrap();
    assert_eq!(result, default_key);
}

#[test]
#[serial]
fn test_resolve_ssh_key_file_not_found_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY"]);
    let temp_home = tempfile::tempdir().unwrap();
    let temp_keys = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    let nonexistent_key = temp_keys.path().join("nonexistent_key");
    create_global_config_with_ssh_key(&temp_home, nonexistent_key.to_str().unwrap());

    let result = super::resolve_ssh_key_descriptor(None, None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("does not exist") || err_msg.contains("not found"));
}

#[test]
#[serial]
fn test_resolve_ssh_key_no_source_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY", "HOME"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    let fake_home = tempfile::tempdir().unwrap();
    env::set_var("HOME", fake_home.path());

    let result = super::resolve_ssh_key_descriptor(None, None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("not configured") || err_msg.contains("not found"));
}

#[test]
#[serial]
fn test_resolve_ssh_key_priority_order() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY"]);
    let temp_home = tempfile::tempdir().unwrap();
    let temp_keys = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    let cli_key = create_ssh_key_file(&temp_keys, "cli_key");
    let global_key = create_ssh_key_file(&temp_keys, "global_key");
    create_global_config_with_ssh_key(&temp_home, global_key.to_str().unwrap());

    let cli_result = super::resolve_ssh_key_descriptor(Some(cli_key.clone()), None)
        .map(|descriptor| descriptor.to_path_buf())
        .unwrap();
    assert_eq!(cli_result, cli_key);

    let global_result = super::resolve_ssh_key_descriptor(None, None)
        .map(|descriptor| descriptor.to_path_buf())
        .unwrap();
    assert_eq!(global_result, global_key);
}

#[test]
#[serial]
fn test_resolve_ssh_key_tilde_expansion() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_SSH_KEY", "HOME"]);
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    let fake_home = tempfile::tempdir().unwrap();
    let ssh_dir = fake_home.path().join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let key_path = ssh_dir.join("my_key");
    fs::write(&key_path, "dummy key").unwrap();
    env::set_var("HOME", fake_home.path());
    let config_path = temp_home.path().join("config.toml");
    fs::write(&config_path, "ssh_key = \"~/.ssh/my_key\"\n").unwrap();

    let result = super::resolve_ssh_key_descriptor(None, None)
        .map(|descriptor| descriptor.to_path_buf())
        .unwrap();
    assert_eq!(result, key_path);
}

#[test]
#[serial]
fn test_resolve_ssh_key_candidate_default_missing() {
    let _guard = EnvGuard::new(&["HOME", "SECRETENV_SSH_KEY"]);
    env::set_var("HOME", "/tmp/test_home");
    env::remove_var("SECRETENV_SSH_KEY");

    let result = super::resolve_ssh_key_candidate(None, None).unwrap();
    assert_eq!(result.source, super::SshKeySource::Default);
    assert_eq!(result.path, PathBuf::from("/tmp/test_home/.ssh/id_ed25519"));
    assert!(!result.exists);
}

#[test]
#[serial]
fn test_resolve_ssh_key_candidate_explicit_missing() {
    let _guard = EnvGuard::new(&["SECRETENV_SSH_KEY"]);
    env::set_var("SECRETENV_SSH_KEY", "/nonexistent/key/path");

    let result = super::resolve_ssh_key_candidate(None, None).unwrap();
    assert_eq!(result.source, super::SshKeySource::Env);
    assert_eq!(result.path, PathBuf::from("/nonexistent/key/path"));
    assert!(!result.exists);
}

#[test]
#[serial]
fn test_resolve_ssh_key_candidate_cli_priority() {
    let _guard = EnvGuard::new(&["SECRETENV_SSH_KEY"]);
    env::set_var("SECRETENV_SSH_KEY", "/env/key/path");

    let cli_path = PathBuf::from("/cli/key/path");
    let result = super::resolve_ssh_key_candidate(Some(cli_path.clone()), None).unwrap();
    assert_eq!(result.source, super::SshKeySource::Cli);
    assert_eq!(result.path, cli_path);
}
