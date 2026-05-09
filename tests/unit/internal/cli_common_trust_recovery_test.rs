// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;

use crate::app::context::options::CommonCommandOptions;
use crate::cli::common::trust::recover_invalid_trust_store_with_reader;
use crate::io::trust::paths::get_trust_store_file_path;
use tempfile::TempDir;

fn build_options(home: &std::path::Path) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.to_path_buf()),
        identity: None,
        debug: false,
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
fn test_recover_invalid_trust_store_with_reader_noninteractive_fails_without_deleting() {
    let temp_dir = TempDir::new().unwrap();
    let options = build_options(temp_dir.path());
    let trust_path = get_trust_store_file_path(temp_dir.path(), "alice@example.com");
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();

    let error = recover_invalid_trust_store_with_reader(
        &options,
        "alice@example.com",
        build_reset_required_error(),
        Cursor::new(Vec::<u8>::new()),
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("non-interactive"));
    assert!(trust_path.exists());
}
