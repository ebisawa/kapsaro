// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for io/config/bootstrap and io/ssh/agent/validation modules

use secretenv_core::cli_api::test_support::storage::ssh::agent::validation::validate_key_present;
use std::path::Path;

#[test]
fn test_validate_member_handle_accepts_common_identifier() {
    let result =
        secretenv_core::cli_api::test_support::storage::config::bootstrap::validate_member_handle(
            "alice@example.com",
        );

    assert!(result.is_ok(), "valid member handle should be accepted");
}

#[test]
fn test_validate_member_handle_rejects_invalid_identifier() {
    let error =
        secretenv_core::cli_api::test_support::storage::config::bootstrap::validate_member_handle(
            "../alice",
        )
        .unwrap_err();

    assert!(
        error.contains("member_handle must start with alphanumeric"),
        "unexpected error: {error}"
    );
}

// ---------------------------------------------------------------------------
// validation.rs tests (validate_key_present - pure function, no agent needed)
// ---------------------------------------------------------------------------

#[test]
fn test_validate_key_present() {
    let socket_path = Path::new("/tmp/test-ssh-agent.sock");
    let result = validate_key_present(true, socket_path);
    assert!(
        result.is_ok(),
        "validate_key_present(true) should succeed, got: {:?}",
        result
    );
}

#[test]
fn test_validate_key_present_error_when_missing() {
    let socket_path = Path::new("/tmp/test-ssh-agent.sock");
    let result = validate_key_present(false, socket_path);
    assert!(
        result.is_err(),
        "validate_key_present(false) should return an error"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("does not have the requested SSH public key"),
        "error should explain that the key is missing, got: {}",
        err_msg
    );
}

#[test]
fn test_validate_key_present_error_mentions_socket() {
    let socket_path = Path::new("/run/user/1000/ssh-agent.sock");
    let result = validate_key_present(false, socket_path);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("/run/user/1000/ssh-agent.sock"),
        "error should include the socket path, got: {}",
        err_msg
    );
    // Should also suggest ssh-add -L for troubleshooting
    assert!(
        err_msg.contains("ssh-add -L"),
        "error should suggest ssh-add -L, got: {}",
        err_msg
    );
}
