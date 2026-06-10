// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for keystore path resolution

use crate::io::keystore::paths::{
    get_active_file_path_from_root, get_key_path_from_root, get_keystore_root_from_base,
    get_member_keystore_path_from_root, get_private_key_file_path_from_root,
    get_public_key_file_path_from_root,
};
use std::path::PathBuf;

#[test]
fn test_keystore_paths_structure() {
    let base_dir = PathBuf::from("/tmp/test");
    let keystore_root = get_keystore_root_from_base(&base_dir);
    assert_eq!(keystore_root, PathBuf::from("/tmp/test/keys"));

    let member_handle = "alice";
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    // Test member path
    let member_path = get_member_keystore_path_from_root(&keystore_root, member_handle);
    assert_eq!(member_path, PathBuf::from("/tmp/test/keys/alice"));

    // Test key path
    let key_path = get_key_path_from_root(&keystore_root, member_handle, kid);
    assert_eq!(
        key_path,
        PathBuf::from("/tmp/test/keys/alice/7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")
    );

    // Test private key file path
    let private_path = get_private_key_file_path_from_root(&keystore_root, member_handle, kid);
    assert_eq!(
        private_path,
        PathBuf::from("/tmp/test/keys/alice/7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD/private.json")
    );

    // Test public key file path
    let public_path = get_public_key_file_path_from_root(&keystore_root, member_handle, kid);
    assert_eq!(
        public_path,
        PathBuf::from("/tmp/test/keys/alice/7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD/public.json")
    );

    // Test active file path
    let active_path = get_active_file_path_from_root(&keystore_root, member_handle);
    assert_eq!(active_path, PathBuf::from("/tmp/test/keys/alice/active"));
}
