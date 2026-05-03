// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for io/config/bootstrap and io/ssh/agent/validation modules

use secretenv::io::config::bootstrap::validate_member_handle;
use secretenv::io::ssh::agent::validation::validate_key_present;
use std::path::Path;

// ---------------------------------------------------------------------------
// bootstrap.rs tests
// ---------------------------------------------------------------------------

// Note: bootstrap_member_handle() uses std::io::stdin().is_terminal() which
// may return true when tests are run from a real terminal, causing the
// function to block waiting for interactive input. We only test the
// validate_member_handle helper here, which is a pure function.

#[test]
fn test_validate_member_handle_edge_cases() {
    // Max length (254 chars) should be accepted
    assert!(
        validate_member_handle(&"a".repeat(254)).is_ok(),
        "254-char member_handle should be valid"
    );

    // 255 chars should be rejected
    assert!(
        validate_member_handle(&"a".repeat(255)).is_err(),
        "255-char member_handle should be invalid"
    );

    // Dots in the middle are valid
    assert!(
        validate_member_handle("alice.bob").is_ok(),
        "dots in middle should be valid"
    );

    // Underscores in the middle are valid
    assert!(
        validate_member_handle("alice_bob").is_ok(),
        "underscores in middle should be valid"
    );

    // Unicode characters are not allowed (only ASCII alphanumeric + limited specials)
    assert!(
        validate_member_handle("ユーザー").is_err(),
        "unicode characters should be invalid"
    );

    // Mixed valid characters
    assert!(
        validate_member_handle("user.name-123@example.com").is_ok(),
        "mixed valid characters should be accepted"
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

// ---------------------------------------------------------------------------
// Tests merged from config_bootstrap_test.rs
// ---------------------------------------------------------------------------

#[test]
fn test_validate_member_handle_valid() {
    let valid = [
        "alice",
        "bob123",
        "test-user",
        "a",
        "alice@example.com",
        "alice.bob@example.com",
        "alice+tag@example.com",
        "alice_bob@example.com",
        "Alice",
        "aliceBob",
        "Alice@Example.COM",
        "1alice",
        "123user",
        &"a".repeat(254),
    ];
    for id in valid {
        assert!(validate_member_handle(id).is_ok(), "should accept: {}", id);
    }
}

#[test]
fn test_validate_member_handle_invalid() {
    let invalid = [
        ("", "empty"),
        (".alice", "starts with dot"),
        ("@alice", "starts with @"),
        ("-alice", "starts with -"),
        ("_alice", "starts with _"),
        (&"a".repeat(255), "too long"),
        ("alice#bob", "invalid char #"),
        ("alice$bob", "invalid char $"),
        ("alice%bob", "invalid char %"),
        ("alice bob", "space"),
        ("alice!bob", "invalid char !"),
    ];
    for (id, reason) in invalid {
        assert!(
            validate_member_handle(id).is_err(),
            "should reject ({}): {}",
            reason,
            id
        );
    }
}
