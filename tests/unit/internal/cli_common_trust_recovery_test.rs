// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;

use crate::cli::common::trust::recover_invalid_trust_store_with_reader;
use crate::test_utils::member_handle;
use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;
use kapsaro_core::cli_api::app::trust::list::resolve_trust_list_command;
use kapsaro_core::cli_api::app::trust::recovery::observe_trust_store_recovery_from_list_command;
use kapsaro_core::cli_api::test_support::helpers::recovery;
use kapsaro_core::cli_api::test_support::storage::trust::paths::get_trust_store_file_path;
use tempfile::TempDir;

fn build_options(home: &std::path::Path) -> CommonCommandOptions {
    CommonCommandOptions::new().with_home(Some(home.to_path_buf()))
}

fn build_reset_required_error() -> kapsaro_core::Error {
    recovery::build_unparsable_trust_store_error("Local trust store is invalid")
}

#[test]
fn test_recover_invalid_trust_store_with_reader_deletes_file_on_confirmation() {
    let temp_dir = TempDir::new().unwrap();
    let options = build_options(temp_dir.path());
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();

    let command =
        resolve_trust_list_command(&options, Some("alice@example.com".to_string())).unwrap();

    let token = observe_trust_store_recovery_from_list_command(&command);
    recover_invalid_trust_store_with_reader(
        &command,
        token,
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
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();

    let command =
        resolve_trust_list_command(&options, Some("alice@example.com".to_string())).unwrap();

    let token = observe_trust_store_recovery_from_list_command(&command);
    let error = recover_invalid_trust_store_with_reader(
        &command,
        token,
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
