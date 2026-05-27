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

    let message = error.format_user_message();
    assert!(message.contains("Unset requires --force."));
    assert!(message.contains("Reason: non-interactive mode."));
}

#[test]
fn test_confirm_unset_operation_with_reader_rejects_interactive_default_no() {
    let error =
        confirm_unset_operation_with_reader(false, "API_KEY", true, Cursor::new(b"\n".to_vec()))
            .unwrap_err();

    assert!(error
        .format_user_message()
        .contains("Unset operation cancelled"));
}
