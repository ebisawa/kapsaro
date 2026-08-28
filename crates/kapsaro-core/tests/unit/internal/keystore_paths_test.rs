// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for keystore path resolution

use crate::io::keystore::paths::{
    get_keystore_root_from_base, get_private_key_file_path_from_root,
    get_public_key_file_path_from_root,
};
use crate::model::identity::{Kid, MemberHandle};
use std::path::PathBuf;

#[test]
fn test_keystore_paths_structure() {
    let base_dir = PathBuf::from("/tmp/test");
    let keystore_root = get_keystore_root_from_base(&base_dir);
    assert_eq!(keystore_root, PathBuf::from("/tmp/test/keys"));

    let member_handle = MemberHandle::try_from("alice").unwrap();
    let kid = Kid::try_from("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();

    // Test private key file path
    let private_path = get_private_key_file_path_from_root(&keystore_root, &member_handle, &kid);
    assert_eq!(
        private_path,
        PathBuf::from("/tmp/test/keys/alice/7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD/private.json")
    );

    // Test public key file path
    let public_path = get_public_key_file_path_from_root(&keystore_root, &member_handle, &kid);
    assert_eq!(
        public_path,
        PathBuf::from("/tmp/test/keys/alice/7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD/public.json")
    );
}
