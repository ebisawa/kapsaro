// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the member handle identity helpers.
//! Covers the guidance the error carries when no handle could be determined.

use crate::app::context::identity::build_missing_member_handle_error;

/// The operator has to be told both ways out, because a handle that could not
/// be determined is fixed either per command or once in the configuration.
#[test]
fn test_build_missing_member_handle_error_names_both_ways_to_supply_a_handle() {
    let error = build_missing_member_handle_error(false);

    let message = error.format_user_message();
    assert!(
        message.contains("member handle is required but could not be determined"),
        "{message}"
    );
    assert!(
        message.contains("Specify a member handle with --member-handle <handle>"),
        "{message}"
    );
    assert!(
        message.contains("Configure a default member handle explicitly"),
        "{message}"
    );
}

#[test]
fn test_build_missing_member_handle_error_includes_prompt_hint_when_requested() {
    let error = build_missing_member_handle_error(true);

    assert!(error
        .format_user_message()
        .contains("Run in an interactive terminal for prompt"));
}
