// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::io::trust::paths::get_trust_store_file_path;
use tempfile::TempDir;

use super::{execute_trust_store_reset, prepare_trust_store_reset_plan, TrustStoreResetPlan};

fn build_options(home: &std::path::Path) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.to_path_buf()),
        identity: None,
        verbose: false,
        workspace: None,
        ssh_signing_method: None,
    }
}

fn build_reset_required_error() -> crate::Error {
    crate::Error::Verify {
        rule: "E_TRUST_STORE_RESET_REQUIRED".to_string(),
        message: "Local trust store is invalid".to_string(),
    }
}

#[test]
fn test_prepare_trust_store_reset_plan_resolves_delete_target() {
    let temp_dir = TempDir::new().unwrap();
    let options = build_options(temp_dir.path());

    let plan = prepare_trust_store_reset_plan(
        &options,
        "alice@example.com",
        build_reset_required_error(),
        true,
    )
    .unwrap();

    assert_eq!(
        plan.path,
        get_trust_store_file_path(temp_dir.path(), "alice@example.com")
    );
    assert!(plan
        .warning_message
        .contains("Local trust store is invalid"));
}

#[test]
fn test_execute_trust_store_reset_deletes_existing_target() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path = get_trust_store_file_path(temp_dir.path(), "alice@example.com");
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();
    let plan = TrustStoreResetPlan {
        path: trust_path.clone(),
        warning_message: String::new(),
    };

    let outcome = execute_trust_store_reset(&plan).unwrap();

    assert_eq!(outcome.path, trust_path);
    assert!(!outcome.path.exists());
}

#[test]
fn test_execute_trust_store_reset_allows_missing_target() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path = get_trust_store_file_path(temp_dir.path(), "alice@example.com");
    let plan = TrustStoreResetPlan {
        path: trust_path.clone(),
        warning_message: String::new(),
    };

    let outcome = execute_trust_store_reset(&plan).unwrap();

    assert_eq!(outcome.path, trust_path);
    assert!(!outcome.path.exists());
}

#[test]
fn test_prepare_trust_store_reset_plan_noninteractive_fails_without_deleting() {
    let temp_dir = TempDir::new().unwrap();
    let options = build_options(temp_dir.path());
    let trust_path = get_trust_store_file_path(temp_dir.path(), "alice@example.com");
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();

    let error = prepare_trust_store_reset_plan(
        &options,
        "alice@example.com",
        build_reset_required_error(),
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("non-interactive"));
    assert!(trust_path.exists());
}
