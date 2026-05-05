// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for keystore storage

use secretenv::io::keystore::storage::list_member_handles;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_list_member_handles_empty() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_root = temp_dir.path();

    let result = list_member_handles(keystore_root).unwrap();
    assert_eq!(result, Vec::<String>::new());
}

#[test]
fn test_list_member_handles_multiple_members() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_root = temp_dir.path();

    // Create member directories
    fs::create_dir_all(keystore_root.join("alice@example.com")).unwrap();
    fs::create_dir_all(keystore_root.join("bob@example.com")).unwrap();
    fs::create_dir_all(keystore_root.join("charlie@example.com")).unwrap();

    let result = list_member_handles(keystore_root).unwrap();
    assert_eq!(
        result,
        vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
            "charlie@example.com".to_string()
        ]
    );
}

#[test]
fn test_list_member_handles_nonexistent_keystore() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_root = temp_dir.path().join("nonexistent");

    let result = list_member_handles(&keystore_root).unwrap();
    assert_eq!(result, Vec::<String>::new());
}
