// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for keystore active key management

use secretenv::io::keystore::active::{clear_active_kid, load_active_kid, set_active_kid};
use secretenv::support::limits::MAX_ACTIVE_KID_FILE_SIZE;
use tempfile::TempDir;

#[test]
fn test_set_and_load_active_kid() {
    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_handle = "alice@example.com";
    let test_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    set_active_kid(member_handle, test_kid, keystore_root).unwrap();
    let active = load_active_kid(member_handle, keystore_root).unwrap();

    assert_eq!(active, Some(test_kid.to_string()));
}

#[test]
fn test_clear_active_kid() {
    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_handle = "alice@example.com";
    let test_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    set_active_kid(member_handle, test_kid, keystore_root).unwrap();
    clear_active_kid(member_handle, keystore_root).unwrap();

    let active = load_active_kid(member_handle, keystore_root).unwrap();
    assert_eq!(active, None);
}

#[test]
fn test_set_active_kid_invalid_length() {
    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_handle = "alice@example.com";
    let invalid_kid = "7M2Q";

    let err = set_active_kid(member_handle, invalid_kid, keystore_root).unwrap_err();
    assert!(err.to_string().contains("32 Crockford Base32 characters"));
}

#[test]
fn test_load_active_kid_invalid_format() {
    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_handle = "alice@example.com";
    let invalid_kid = "invalid\n";

    let active_path = keystore_root.join(member_handle).join("active");
    std::fs::create_dir_all(active_path.parent().unwrap()).unwrap();
    std::fs::write(&active_path, invalid_kid).unwrap();

    let err = load_active_kid(member_handle, keystore_root).unwrap_err();
    assert!(err.to_string().contains("Crockford Base32"));
}

#[cfg(unix)]
#[test]
fn test_load_active_kid_rejects_symlinked_active_file() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_handle = "alice@example.com";
    let active_path = keystore_root.join(member_handle).join("active");
    let target = keystore_root.join("target-active");
    std::fs::create_dir_all(active_path.parent().unwrap()).unwrap();
    std::fs::write(&target, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD\n").unwrap();
    symlink(&target, &active_path).unwrap();

    let err = load_active_kid(member_handle, keystore_root).unwrap_err();

    assert!(err.to_string().contains("symlink"));
}

#[test]
fn test_load_active_kid_rejects_oversized_file() {
    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_handle = "alice@example.com";
    let active_path = keystore_root.join(member_handle).join("active");
    std::fs::create_dir_all(active_path.parent().unwrap()).unwrap();
    std::fs::write(&active_path, "A".repeat(MAX_ACTIVE_KID_FILE_SIZE + 1)).unwrap();

    let err = load_active_kid(member_handle, keystore_root).unwrap_err();

    assert!(err.to_string().contains("maximum size limit"));
}

#[test]
fn test_set_active_kid_normalizes_display_form() {
    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_handle = "alice@example.com";

    set_active_kid(
        member_handle,
        "7m2q-9d4r-1h8v-w6pk-t3xn-c5jy-2f9a-r8gd",
        keystore_root,
    )
    .unwrap();

    let active = load_active_kid(member_handle, keystore_root).unwrap();
    assert_eq!(active.as_deref(), Some("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"));
}
