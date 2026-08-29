// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for config::resolution::member_handle::resolve_member_handle_with_fallback

use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::test_utils::{
    create_local_state_dir, local_state_temp_dir, write_local_state_file, EnvGuard,
};
use crate::{
    io::keystore::access::KeystoreAccess, model::identity::MemberHandle,
    support::fs::anchor::AnchoredDir,
};
use serial_test::serial;
use std::env;
use std::fs;
use tempfile::TempDir;

fn save_global_config(temp_home: &TempDir, member_handle: &str) {
    let config_path = temp_home.path().join("config.toml");
    write_local_state_file(
        &config_path,
        format!("member_handle = \"{}\"\n", member_handle),
    );
}

fn setup_keystore(temp_dir: &TempDir, member_handles: &[&str]) {
    let keystore_root = temp_dir.path().join("keys");
    create_local_state_dir(&keystore_root);
    for &id in member_handles {
        create_local_state_dir(&keystore_root.join(id));
    }
}

#[test]
#[serial]
fn test_resolve_member_handle_from_cli_argument() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::set_var("KAPSARO_MEMBER_HANDLE", "env-member");
    save_global_config(&temp_home, "config-member");
    setup_keystore(&temp_home, &["keystore-member"]);

    let result = super::resolve_member_handle_with_fallback(
        Some("cli-member".to_string()),
        Some(temp_home.path()),
    )
    .unwrap();

    assert_eq!(result, Some("cli-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_handle_cli_invalid_error() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    setup_keystore(&temp_home, &[]);

    let result = super::resolve_member_handle_with_fallback(
        Some("invalid member handle!".to_string()),
        Some(temp_home.path()),
    );

    assert!(result.is_err());
}

#[test]
#[serial]
fn test_resolve_member_handle_from_env_var() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::set_var("KAPSARO_MEMBER_HANDLE", "env-member");
    save_global_config(&temp_home, "config-member");
    setup_keystore(&temp_home, &["keystore-member"]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("env-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_handle_env_invalid_error() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::set_var("KAPSARO_MEMBER_HANDLE", "invalid member!");
    setup_keystore(&temp_home, &[]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path()));

    assert!(result.is_err());
}

#[test]
#[serial]
fn test_resolve_member_handle_from_global_config() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::remove_var("KAPSARO_MEMBER_HANDLE");
    save_global_config(&temp_home, "config-member");
    setup_keystore(&temp_home, &["keystore-member"]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("config-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_handle_config_invalid_error() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::remove_var("KAPSARO_MEMBER_HANDLE");
    save_global_config(&temp_home, "invalid member!");
    setup_keystore(&temp_home, &[]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path()));

    assert!(result.is_err());
}

#[test]
#[serial]
fn test_resolve_member_handle_from_keystore_single_member() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::remove_var("KAPSARO_MEMBER_HANDLE");
    setup_keystore(&temp_home, &["keystore-member"]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, Some("keystore-member".to_string()));
}

#[test]
#[serial]
fn test_resolve_member_handle_keystore_multiple_members_returns_none() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::remove_var("KAPSARO_MEMBER_HANDLE");
    setup_keystore(&temp_home, &["alice", "bob"]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_resolve_member_handle_keystore_empty_returns_none() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::remove_var("KAPSARO_MEMBER_HANDLE");
    setup_keystore(&temp_home, &[]);

    let result = super::resolve_member_handle_with_fallback(None, Some(temp_home.path())).unwrap();

    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_fixed_keystore_resolver_preserves_source_priority() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::set_var("KAPSARO_MEMBER_HANDLE", "env-member");
    save_global_config(&temp_home, "config-member");
    setup_keystore(&temp_home, &["keystore-member"]);
    let home = AnchoredDir::open(
        temp_home.path(),
        crate::support::fs::relative::DirectoryScope::LocalState,
        "test home",
    )
    .unwrap();
    let access = KeystoreAccess::open_from_anchored_home(&home).unwrap();
    let config = GlobalConfigSnapshot::for_home(Some(&home));
    let resolver = super::MemberHandleResolver::fixed(&config, Some(&access));

    let cli = resolver
        .resolve(Some("cli-member".to_string()))
        .unwrap()
        .unwrap();
    assert_eq!(cli, "cli-member");

    let env_member = resolver.resolve(None).unwrap().unwrap();
    assert_eq!(env_member, "env-member");

    env::remove_var("KAPSARO_MEMBER_HANDLE");
    let configured = resolver.resolve(None).unwrap().unwrap();
    assert_eq!(configured, "config-member");

    // A snapshot answers from the file it read, so the keystore fallback is
    // reached by the resolver of a run that started without a config file.
    fs::remove_file(temp_home.path().join("config.toml")).unwrap();
    let config_without_file = GlobalConfigSnapshot::for_home(Some(&home));
    let fallback = super::MemberHandleResolver::fixed(&config_without_file, Some(&access))
        .resolve(None)
        .unwrap()
        .unwrap();
    assert_eq!(fallback, "keystore-member");
}

#[test]
#[serial]
fn test_fixed_keystore_resolver_uses_opened_directory_identity() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    let replacement_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::remove_var("KAPSARO_MEMBER_HANDLE");
    setup_keystore(&temp_home, &["opened-member"]);
    setup_keystore(&replacement_home, &["replacement-member"]);
    let home = AnchoredDir::open(
        temp_home.path(),
        crate::support::fs::relative::DirectoryScope::LocalState,
        "test home",
    )
    .unwrap();
    let access = KeystoreAccess::open_from_anchored_home(&home).unwrap();

    fs::rename(
        temp_home.path().join("keys"),
        temp_home.path().join("keys.opened"),
    )
    .unwrap();
    fs::rename(
        replacement_home.path().join("keys"),
        temp_home.path().join("keys"),
    )
    .unwrap();

    let config = GlobalConfigSnapshot::for_home(Some(&home));
    let resolved = super::MemberHandleResolver::fixed(&config, Some(&access))
        .resolve(None)
        .unwrap();

    assert_eq!(
        resolved,
        Some(MemberHandle::try_from("opened-member").unwrap())
    );
}

#[cfg(unix)]
#[test]
#[serial]
fn test_fixed_keystore_resolver_reads_config_from_opened_home_after_path_swap() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_root = local_state_temp_dir();
    let home_path = temp_root.path().join("home");
    let opened_path = temp_root.path().join("home.opened");
    let replacement_path = temp_root.path().join("home.replacement");
    create_local_state_dir(&home_path);
    create_local_state_dir(&replacement_path);
    write_local_state_file(
        &home_path.join("config.toml"),
        "member_handle = \"opened-config-member\"\n",
    );
    write_local_state_file(
        &replacement_path.join("config.toml"),
        "member_handle = \"replacement-config-member\"\n",
    );
    create_local_state_dir(&home_path.join("keys"));
    create_local_state_dir(&replacement_path.join("keys"));
    env::remove_var("KAPSARO_MEMBER_HANDLE");
    let home = AnchoredDir::open(
        &home_path,
        crate::support::fs::relative::DirectoryScope::LocalState,
        "test home",
    )
    .unwrap();
    let access = KeystoreAccess::open_from_anchored_home(&home).unwrap();

    fs::rename(&home_path, &opened_path).unwrap();
    fs::rename(&replacement_path, &home_path).unwrap();

    let config = GlobalConfigSnapshot::for_home(Some(&home));
    let resolved = super::MemberHandleResolver::fixed(&config, Some(&access))
        .resolve(None)
        .unwrap();

    assert_eq!(
        resolved,
        Some(MemberHandle::try_from("opened-config-member").unwrap())
    );
}

#[test]
#[serial]
fn test_fixed_keystore_resolver_omits_unavailable_single_member_fallback() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE"]);
    let temp_home = local_state_temp_dir();
    env::set_var("KAPSARO_HOME", temp_home.path());
    env::remove_var("KAPSARO_MEMBER_HANDLE");

    let home = AnchoredDir::open(
        temp_home.path(),
        crate::support::fs::relative::DirectoryScope::LocalState,
        "test home",
    )
    .unwrap();
    let empty_config = GlobalConfigSnapshot::for_home(Some(&home));
    let resolver = super::MemberHandleResolver::fixed(&empty_config, None);
    assert_eq!(resolver.resolve(None).unwrap(), None);

    // A snapshot answers from the file it read, so the configured handle is
    // reached by the resolver of a run that started after the file was written.
    save_global_config(&temp_home, "config-member");
    let config = GlobalConfigSnapshot::for_home(Some(&home));
    let resolved = super::MemberHandleResolver::fixed(&config, None)
        .resolve(None)
        .unwrap()
        .unwrap();
    assert_eq!(resolved, "config-member");
}
