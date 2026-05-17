// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::ensure_kid_not_in_keystore;

#[test]
fn test_ensure_kid_not_in_keystore_passes_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    // keystore root directory exists but has no members
    let result = ensure_kid_not_in_keystore(dir.path(), "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    assert!(result.is_ok());
}

#[test]
fn test_ensure_kid_not_in_keystore_fails_when_present_any_member() {
    let dir = tempfile::tempdir().unwrap();
    let keystore_root = dir.path();
    std::fs::create_dir_all(
        keystore_root
            .join("alice@example.com")
            .join("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();

    let err =
        ensure_kid_not_in_keystore(keystore_root, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("already exists in keystore"));
    assert!(msg.contains("alice@example.com"));
}
