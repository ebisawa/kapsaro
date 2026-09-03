// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;

use crate::cli::common::trust::recover_invalid_trust_store_with_reader;
use crate::test_utils::member_handle;
use kapsaro_core::api::config::LocalStateSession;
use kapsaro_core::api::trust::list::{
    resolve_trust_list_command as resolve_trust_list_command_with_session, TrustListCommand,
};
use kapsaro_core::api::trust::recovery::observe_trust_store_recovery_from_list_command;
use kapsaro_core::test_support::helpers::recovery;
use kapsaro_core::test_support::storage::trust::paths::get_trust_store_file_path;
use tempfile::TempDir;

fn build_reset_required_error() -> kapsaro_core::Error {
    recovery::build_unparsable_trust_store_error("Local trust store is invalid")
}

fn resolve_trust_list_command(
    path: &std::path::Path,
    owner: kapsaro_core::api::key::MemberHandle,
) -> kapsaro_core::Result<TrustListCommand> {
    let local_state = LocalStateSession::open(path.to_path_buf())?;
    resolve_trust_list_command_with_session(&local_state, owner)
}

#[test]
fn test_recover_invalid_trust_store_with_reader_deletes_file_on_confirmation() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();

    let command =
        resolve_trust_list_command(temp_dir.path(), member_handle("alice@example.com")).unwrap();

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
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();

    let command =
        resolve_trust_list_command(temp_dir.path(), member_handle("alice@example.com")).unwrap();

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
