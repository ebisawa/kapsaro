// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for trust store path resolution

use crate::io::trust::paths::{
    get_trust_store_dir, get_trust_store_file_name, get_trust_store_file_path,
    get_trust_store_owner_handle,
};
use crate::test_utils::member_handle;
use std::path::Path;

#[test]
fn test_get_trust_store_dir() {
    let base = Path::new("/home/alice/.config/kapsaro");
    let dir = get_trust_store_dir(base);
    assert_eq!(dir, Path::new("/home/alice/.config/kapsaro/trust"));
}

#[test]
fn test_trust_store_file_path() {
    let base = Path::new("/home/alice/.config/kapsaro");
    let path = get_trust_store_file_path(base, &member_handle("alice@example.com"));
    assert_eq!(
        path,
        Path::new("/home/alice/.config/kapsaro/trust/alice@example.com.json")
    );
}

#[test]
fn test_trust_store_file_path_simple_member_handle() {
    let base = Path::new("/tmp/test");
    let path = get_trust_store_file_path(base, &member_handle("bob"));
    assert_eq!(path, Path::new("/tmp/test/trust/bob.json"));
}

/// The owner handle a file name was built from reads back out of it, so the
/// directory scan and the write agree on how one name is spelled.
#[test]
fn test_trust_store_owner_handle_reads_back_out_of_the_file_name() {
    let file_name = get_trust_store_file_name(&member_handle("alice@example.com"));

    assert_eq!(
        get_trust_store_owner_handle(&file_name),
        Some("alice@example.com")
    );
}

/// A name that is not spelled the way a trust store is spelled names none.
#[test]
fn test_trust_store_owner_handle_reports_nothing_for_another_spelling() {
    assert_eq!(get_trust_store_owner_handle("alice@example.com"), None);
    assert_eq!(get_trust_store_owner_handle("notes.txt"), None);
}
