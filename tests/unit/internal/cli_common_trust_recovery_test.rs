// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;

use crate::cli::common::trust::recover_invalid_trust_store_with_reader;
use secretenv_core::cli_api::app::context::options::CommonCommandOptions;
use secretenv_core::cli_api::test_support::storage::trust::paths::get_trust_store_file_path;
use tempfile::TempDir;

fn build_options(home: &std::path::Path) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.to_path_buf()),
        identity: None,
        debug: false,
        verbose: false,
        workspace: None,
        ssh_signing_method: None,
        allow_expired_key: false,
    }
}

fn build_reset_required_error() -> secretenv_core::Error {
    secretenv_core::Error::build_verification_error(
        "E_TRUST_STORE_RESET_REQUIRED".to_string(),
        "Local trust store is invalid".to_string(),
    )
}

#[test]
fn test_recover_invalid_trust_store_with_reader_deletes_file_on_confirmation() {
    let temp_dir = TempDir::new().unwrap();
    let options = build_options(temp_dir.path());
    let trust_path = get_trust_store_file_path(temp_dir.path(), "alice@example.com");
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();

    recover_invalid_trust_store_with_reader(
        &options,
        "alice@example.com",
        build_reset_required_error(),
        Cursor::new(b"yes\n".to_vec()),
        true,
    )
    .unwrap();

    assert!(!trust_path.exists());
}

#[test]
fn test_recover_invalid_trust_store_with_reader_keeps_file_when_declined() {
    let temp_dir = TempDir::new().unwrap();
    let options = build_options(temp_dir.path());
    let trust_path = get_trust_store_file_path(temp_dir.path(), "alice@example.com");
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();

    let error = recover_invalid_trust_store_with_reader(
        &options,
        "alice@example.com",
        build_reset_required_error(),
        Cursor::new(b"no\n".to_vec()),
        true,
    )
    .unwrap_err();

    assert!(trust_path.exists());
    assert!(
        error
            .to_string()
            .contains("Local trust store reset was declined"),
        "unexpected error: {error}"
    );
}
