// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/validation module
//!
//! Tests for validation utilities (edge cases).

use secretenv::support::validation::{
    validate_github_login, validate_kv_file_basename, validate_member_id,
};

#[test]
fn test_validate_member_id_valid() {
    assert!(validate_member_id("alice@example.com").is_ok());
    assert!(validate_member_id("user.name@example.com").is_ok());
    assert!(validate_member_id("user+tag@example.com").is_ok());
    assert!(validate_member_id("user_name@example.com").is_ok());
    assert!(validate_member_id("user-name@example.com").is_ok());
}

#[test]
fn test_validate_member_id_empty() {
    assert!(validate_member_id("").is_err());
}

#[test]
fn test_validate_member_id_too_long() {
    let long_id = "a".repeat(255);
    assert!(validate_member_id(&long_id).is_err());
}

#[test]
fn test_validate_member_id_max_length() {
    let max_id = "a".repeat(254);
    assert!(validate_member_id(&max_id).is_ok());
}

#[test]
fn test_validate_member_id_starts_with_non_alphanumeric() {
    assert!(validate_member_id("@example.com").is_err());
    assert!(validate_member_id(".example.com").is_err());
    assert!(validate_member_id("_example.com").is_err());
}

#[test]
fn test_validate_member_id_invalid_characters() {
    assert!(validate_member_id("user#example.com").is_err());
    assert!(validate_member_id("user$example.com").is_err());
    assert!(validate_member_id("user example.com").is_err());
}

#[test]
fn test_validate_github_login_accepts_valid_values() {
    assert!(validate_github_login("alice").is_ok());
    assert!(validate_github_login("alice-gh").is_ok());
    assert!(validate_github_login("A1-b2").is_ok());
    assert!(validate_github_login(&"a".repeat(39)).is_ok());
}

#[test]
fn test_validate_github_login_rejects_invalid_values() {
    for login in [
        "",
        "-alice",
        "alice-",
        "alice--dev",
        "alice/dev",
        "../alice",
        "alice?tab=keys",
        "alice#keys",
        "alice dev",
        "alice_dev",
        "ユーザー",
        &"a".repeat(40),
    ] {
        assert!(
            validate_github_login(login).is_err(),
            "should reject: {}",
            login
        );
    }
}

#[test]
fn test_validate_kv_file_basename_accepts_safe_names() {
    assert!(validate_kv_file_basename("default").is_ok());
    assert!(validate_kv_file_basename("prod").is_ok());
    assert!(validate_kv_file_basename("db.secrets").is_ok());
    assert!(validate_kv_file_basename("foo-bar_1").is_ok());
    assert!(validate_kv_file_basename("Name123").is_ok());
}

#[test]
fn test_validate_kv_file_basename_rejects_empty() {
    assert!(validate_kv_file_basename("").is_err());
}

#[test]
fn test_validate_kv_file_basename_rejects_path_separators() {
    assert!(validate_kv_file_basename("/etc/foo").is_err());
    assert!(validate_kv_file_basename("foo/bar").is_err());
    assert!(validate_kv_file_basename("..\\win").is_err());
    assert!(validate_kv_file_basename("a\\b").is_err());
}

#[test]
fn test_validate_kv_file_basename_rejects_parent_component() {
    assert!(validate_kv_file_basename("..").is_err());
    assert!(validate_kv_file_basename("../x").is_err());
}

#[test]
fn test_validate_kv_file_basename_rejects_leading_dot() {
    assert!(validate_kv_file_basename(".hidden").is_err());
    assert!(validate_kv_file_basename(".").is_err());
}

#[test]
fn test_validate_kv_file_basename_rejects_nul() {
    assert!(validate_kv_file_basename("a\0b").is_err());
}

#[test]
fn test_validate_kv_file_basename_rejects_non_printable_ascii() {
    assert!(validate_kv_file_basename("日本語").is_err());
    assert!(validate_kv_file_basename("tab\there").is_err());
    assert!(validate_kv_file_basename("bell\x07").is_err());
}
