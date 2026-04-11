// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::confirm_member_remove_with_reader;
use std::io::Cursor;

#[test]
fn test_confirm_member_remove_with_reader_accepts_force() {
    let result = confirm_member_remove_with_reader(
        true,
        "alice@example.com",
        false,
        Cursor::new(Vec::<u8>::new()),
    );

    assert!(result.is_ok());
}

#[test]
fn test_confirm_member_remove_with_reader_rejects_non_interactive_without_force() {
    let error = confirm_member_remove_with_reader(
        false,
        "alice@example.com",
        false,
        Cursor::new(Vec::<u8>::new()),
    )
    .unwrap_err();

    assert!(error
        .user_message()
        .contains("without --force in non-interactive mode"));
}

#[test]
fn test_confirm_member_remove_with_reader_accepts_interactive_yes() {
    let result = confirm_member_remove_with_reader(
        false,
        "alice@example.com",
        true,
        Cursor::new(b"y\n".to_vec()),
    );

    assert!(result.is_ok());
}

#[test]
fn test_confirm_member_remove_with_reader_rejects_interactive_default_no() {
    let error = confirm_member_remove_with_reader(
        false,
        "alice@example.com",
        true,
        Cursor::new(b"\n".to_vec()),
    )
    .unwrap_err();

    assert!(error.user_message().contains("Member removal cancelled"));
}
