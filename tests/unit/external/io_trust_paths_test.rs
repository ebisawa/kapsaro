// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for trust store path resolution

use secretenv_core::cli_api::test_support::storage::trust::paths::{
    get_trust_store_dir, get_trust_store_file_path,
};
use std::path::Path;

#[test]
fn test_get_trust_store_dir() {
    let base = Path::new("/home/alice/.config/secretenv");
    let dir = get_trust_store_dir(base);
    assert_eq!(dir, Path::new("/home/alice/.config/secretenv/trust"));
}

#[test]
fn test_trust_store_file_path() {
    let base = Path::new("/home/alice/.config/secretenv");
    let path = get_trust_store_file_path(base, "alice@example.com");
    assert_eq!(
        path,
        Path::new("/home/alice/.config/secretenv/trust/alice@example.com.json")
    );
}

#[test]
fn test_trust_store_file_path_simple_member_handle() {
    let base = Path::new("/tmp/test");
    let path = get_trust_store_file_path(base, "bob");
    assert_eq!(path, Path::new("/tmp/test/trust/bob.json"));
}
