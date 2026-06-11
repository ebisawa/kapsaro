// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Internal tests for app-layer public key export.
//! Verifies exported PublicKey fields separately from CLI presentation.

use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::app::key::manage::export_key_command;
use crate::io::keystore::active::load_active_kid;
use crate::model::public_key::PublicKey;
use crate::model::wire::format::PUBLIC_KEY_V1;
use crate::support::kid::format_kid_display;
use crate::test_utils::{setup_test_keystore_from_fixtures, EnvGuard, ALICE_MEMBER_HANDLE};

const EXPORT_ENV_VARS: &[&str] = &["KAPSARO_HOME", "KAPSARO_MEMBER_HANDLE", "KAPSARO_WORKSPACE"];

fn build_options(home: &Path) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.to_path_buf()),
        identity: None,
        debug: false,
        verbose: false,
        workspace: None,
        ssh_signing_method: None,
        allow_expired_key: false,
        allow_non_member: false,
    }
}

fn active_kid(home: &Path) -> String {
    load_active_kid(ALICE_MEMBER_HANDLE, &home.join("keys"))
        .unwrap()
        .unwrap()
}

fn load_exported_public_key(path: &Path) -> PublicKey {
    let exported_json = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&exported_json).unwrap()
}

fn clean_export_env() -> EnvGuard {
    let guard = EnvGuard::new(EXPORT_ENV_VARS);
    for key in EXPORT_ENV_VARS {
        std::env::remove_var(key);
    }
    guard
}

#[test]
fn test_export_key_command_explicit_kid_exports_public_key_fields() {
    let _env = clean_export_env();
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let kid = active_kid(home.path());
    let out = home.path().join("explicit-public.json");

    let result = export_key_command(
        &build_options(home.path()),
        Some(ALICE_MEMBER_HANDLE.to_string()),
        Some(kid.clone()),
        &out,
    )
    .unwrap();
    let exported = load_exported_public_key(&out);

    assert_eq!(result.kid, kid);
    assert_eq!(exported.protected.kid, kid);
    assert_eq!(exported.protected.subject_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(exported.protected.format, PUBLIC_KEY_V1);
}

#[test]
fn test_export_key_command_active_key_exports_public_key_format() {
    let _env = clean_export_env();
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let out = home.path().join("active-public.json");

    export_key_command(
        &build_options(home.path()),
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        &out,
    )
    .unwrap();
    let exported = load_exported_public_key(&out);

    assert_eq!(exported.protected.format, PUBLIC_KEY_V1);
}

#[test]
fn test_export_key_command_display_kid_exports_canonical_public_key_kid() {
    let _env = clean_export_env();
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let kid = active_kid(home.path());
    let out = home.path().join("display-public.json");

    export_key_command(
        &build_options(home.path()),
        Some(ALICE_MEMBER_HANDLE.to_string()),
        Some(format_kid_display(&kid).unwrap()),
        &out,
    )
    .unwrap();
    let exported = load_exported_public_key(&out);

    assert_eq!(exported.protected.kid, kid);
}
