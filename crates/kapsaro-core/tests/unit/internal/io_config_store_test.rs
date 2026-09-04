// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for io/config/store module
//!
//! Tests for the fd-relative config file load, set and unset operations.

use crate::io::config::store::{
    load_config_file_from_anchored_home, set_config_value, unset_config_value,
};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::DirectoryScope;
use crate::support::limits::MAX_CONFIG_FILE_SIZE;
use crate::support::warning::LocalStateWarningGuard;
use crate::test_utils::{ensure_local_state_dir, local_state_temp_dir, save_local_state_file};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Barrier};
use tempfile::TempDir;

fn open_home(path: &Path) -> AnchoredDir {
    AnchoredDir::open(path, DirectoryScope::LocalState, "test local state root").unwrap()
}

/// Create a home directory holding the given config file content.
fn home_with_config(tmp: &TempDir, content: &str) -> AnchoredDir {
    save_local_state_file(&tmp.path().join("config.toml"), content);
    open_home(tmp.path())
}

// ---------------------------------------------------------------------------
// load tests
// ---------------------------------------------------------------------------

#[test]
fn test_load_config_file_nonexistent() {
    let tmp = local_state_temp_dir();
    let home = open_home(tmp.path());

    let result = load_config_file_from_anchored_home(&home).unwrap();

    assert!(
        result.is_empty(),
        "a home without a config file should return an empty map"
    );
}

#[test]
fn test_load_config_file_empty() {
    let tmp = local_state_temp_dir();
    let home = home_with_config(&tmp, "");

    let result = load_config_file_from_anchored_home(&home).unwrap();

    assert!(result.is_empty(), "empty file should return empty map");
}

#[test]
fn test_load_config_file_valid() {
    let tmp = local_state_temp_dir();
    let home = home_with_config(
        &tmp,
        r#"
member_handle = "alice@example.com"
ssh_signing_method = "ssh-agent"
ssh_keygen_command = "/usr/bin/ssh-keygen"
ssh_add_command = "/usr/bin/ssh-add"
"#,
    );

    let result = load_config_file_from_anchored_home(&home).unwrap();

    assert_eq!(result.len(), 4);
    assert_eq!(result.get("member_handle").unwrap(), "alice@example.com");
    assert_eq!(result.get("ssh_signing_method").unwrap(), "ssh-agent");
    assert_eq!(
        result.get("ssh_keygen_command").unwrap(),
        "/usr/bin/ssh-keygen"
    );
    assert_eq!(result.get("ssh_add_command").unwrap(), "/usr/bin/ssh-add");
}

/// The config file is local state, so it is read through the home descriptor
/// and a link standing in its place is refused like any other non-regular file.
#[cfg(unix)]
#[test]
fn test_load_config_file_rejects_symlinked_config_file() {
    use std::os::unix::fs::symlink;

    let tmp = local_state_temp_dir();
    let target = tmp.path().join("target.toml");
    save_local_state_file(&target, "member_handle = \"alice@example.com\"\n");
    symlink(&target, tmp.path().join("config.toml")).unwrap();
    let home = open_home(tmp.path());

    let error = load_config_file_from_anchored_home(&home).unwrap_err();

    assert!(
        error.to_string().contains("non-regular file"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_load_config_file_invalid_toml() {
    let tmp = local_state_temp_dir();
    let home = home_with_config(&tmp, "this is not valid = toml [[[");

    let error = load_config_file_from_anchored_home(&home).unwrap_err();

    assert!(
        error.to_string().contains("Invalid TOML"),
        "error should mention invalid TOML, got: {error}"
    );
}

#[test]
fn test_load_config_file_rejects_oversized_file() {
    let tmp = local_state_temp_dir();
    let home = home_with_config(&tmp, &"a".repeat(MAX_CONFIG_FILE_SIZE + 1));

    let error = load_config_file_from_anchored_home(&home).unwrap_err();

    assert!(error.to_string().contains("maximum size limit"));
}

#[test]
fn test_load_config_file_ignores_non_string_values() {
    let tmp = local_state_temp_dir();
    let home = home_with_config(
        &tmp,
        r#"
string_key = "hello"
int_key = 42
bool_key = true
float_key = 3.14
"#,
    );

    let result = load_config_file_from_anchored_home(&home).unwrap();

    assert_eq!(result.len(), 1, "only string values should be included");
    assert_eq!(result.get("string_key").unwrap(), "hello");
}

// ---------------------------------------------------------------------------
// set_config_value tests
// ---------------------------------------------------------------------------

#[test]
fn test_set_config_value_new_file() {
    let tmp = local_state_temp_dir();
    let home = open_home(tmp.path());

    set_config_value(&home, "member_handle", "bob@example.com").unwrap();

    let config = load_config_file_from_anchored_home(&home).unwrap();
    assert_eq!(config.get("member_handle").unwrap(), "bob@example.com");
}

#[test]
fn test_set_config_value_update_existing() {
    let tmp = local_state_temp_dir();
    let home = home_with_config(&tmp, "member_handle = \"old@example.com\"\n");

    set_config_value(&home, "member_handle", "new@example.com").unwrap();

    let config = load_config_file_from_anchored_home(&home).unwrap();
    assert_eq!(config.get("member_handle").unwrap(), "new@example.com");
}

#[test]
fn test_config_update_does_not_acquire_a_directory_lock() {
    let tmp = local_state_temp_dir();
    let home = open_home(tmp.path());

    crate::support::fs::lock::with_exclusive_locked_directory(&home, |_| {
        set_config_value(&home, "member_handle", "alice@example.com")
    })
    .unwrap();

    assert_eq!(
        load_config_file_from_anchored_home(&home)
            .unwrap()
            .get("member_handle")
            .map(String::as_str),
        Some("alice@example.com")
    );
}

#[test]
fn test_concurrent_config_updates_leave_complete_toml() {
    const WRITERS: usize = 8;
    let tmp = local_state_temp_dir();
    let root = tmp.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(WRITERS + 1));
    let mut workers = Vec::new();

    for index in 0..WRITERS {
        let root = root.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let home = open_home(&root);
            barrier.wait();
            set_config_value(&home, "member_handle", &format!("writer-{index}"))
        }));
    }

    barrier.wait();
    for worker in workers {
        worker.join().unwrap().unwrap();
    }

    let content = fs::read_to_string(root.join("config.toml")).unwrap();
    let parsed: toml::Table = toml::from_str(&content).unwrap();
    let value = parsed
        .get("member_handle")
        .and_then(toml::Value::as_str)
        .unwrap();
    assert!(value.starts_with("writer-"), "{content}");
}

#[cfg(unix)]
#[test]
fn test_set_config_value_writes_the_config_file_owner_only() {
    let tmp = local_state_temp_dir();
    let home = open_home(tmp.path());

    set_config_value(&home, "member_handle", "bob@example.com").unwrap();

    let mode = fs::metadata(tmp.path().join("config.toml"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

/// A name standing as a link is refused rather than replaced. The write
/// publishes by rename, so the link would be swapped out instead of followed,
/// and it is the only sign the name was repointed. The read path refuses the
/// same entry, so what kapsaro declines to read it declines to overwrite.
#[cfg(unix)]
#[test]
fn test_save_config_file_refuses_a_symlink_standing_in_its_place() {
    use std::os::unix::fs::symlink;

    let tmp = local_state_temp_dir();
    let target = tmp.path().join("target.toml");
    save_local_state_file(&target, "member_handle = \"alice@example.com\"\n");
    symlink(&target, tmp.path().join("config.toml")).unwrap();
    let home = open_home(tmp.path());

    let error = super::save_toml_table(&home, &toml::Table::new()).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(
        error.to_string().contains("symlink"),
        "unexpected error: {error}"
    );
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        "member_handle = \"alice@example.com\"\n"
    );
}

// ---------------------------------------------------------------------------
// unset_config_value tests
// ---------------------------------------------------------------------------

#[test]
fn test_unset_config_value() {
    let tmp = local_state_temp_dir();
    let home = home_with_config(
        &tmp,
        "member_handle = \"alice@example.com\"\nssh_signing_method = \"ssh-agent\"\n",
    );

    unset_config_value(&home, "member_handle").unwrap();

    let config = load_config_file_from_anchored_home(&home).unwrap();
    assert_eq!(
        config.keys().collect::<Vec<_>>(),
        vec!["ssh_signing_method"],
        "only the removed key should be gone"
    );
}

#[test]
fn test_unset_config_value_not_found() {
    let tmp = local_state_temp_dir();
    let home = home_with_config(&tmp, "member_handle = \"alice@example.com\"\n");

    let error = unset_config_value(&home, "nonexistent_key").unwrap_err();

    assert!(
        error.to_string().contains("not found"),
        "error should mention key not found, got: {error}"
    );
}

/// The config file lives in local state, so a group-readable home directory
/// holding it is named in a warning while the read carries on.
#[cfg(unix)]
#[test]
fn test_load_config_file_warns_about_insecure_home_directory_permissions() {
    let tmp = local_state_temp_dir();
    let base_dir = tmp.path().join("kapsaro");
    ensure_local_state_dir(&base_dir);
    save_local_state_file(
        &base_dir.join("config.toml"),
        "member_handle = \"alice@example.com\"\n",
    );
    fs::set_permissions(&base_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let home = open_home(&base_dir);

    let guard = LocalStateWarningGuard::new();
    let config = load_config_file_from_anchored_home(&home).unwrap();
    let warnings = guard.take_reasons();

    assert_eq!(
        config.get("member_handle").map(String::as_str),
        Some("alice@example.com")
    );
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("Insecure permissions 0755"),
        "{warnings:?}"
    );
    assert!(warnings[0].contains("expected 0700"), "{warnings:?}");
    assert!(warnings[0].contains("chmod 0700"), "{warnings:?}");
}
