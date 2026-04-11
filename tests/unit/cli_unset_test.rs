// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::confirm_unset_operation_with_reader;
use std::io::Cursor;

#[test]
fn test_confirm_unset_operation_with_reader_accepts_force() {
    let result =
        confirm_unset_operation_with_reader(true, "API_KEY", false, Cursor::new(Vec::<u8>::new()));

    assert!(result.is_ok());
}

#[test]
fn test_confirm_unset_operation_with_reader_rejects_non_interactive_without_force() {
    let error =
        confirm_unset_operation_with_reader(false, "API_KEY", false, Cursor::new(Vec::<u8>::new()))
            .unwrap_err();

    assert!(error
        .user_message()
        .contains("without --force in non-interactive mode"));
}

#[test]
fn test_confirm_unset_operation_with_reader_accepts_interactive_yes() {
    let result =
        confirm_unset_operation_with_reader(false, "API_KEY", true, Cursor::new(b"y\n".to_vec()));

    assert!(result.is_ok());
}

#[test]
fn test_confirm_unset_operation_with_reader_rejects_interactive_default_no() {
    let error =
        confirm_unset_operation_with_reader(false, "API_KEY", true, Cursor::new(b"\n".to_vec()))
            .unwrap_err();

    assert!(error.user_message().contains("Unset operation cancelled"));
}
