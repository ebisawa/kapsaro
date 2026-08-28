// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/services/keystore/resolver module
//!
//! Tests for keystore resolver.

use crate::io::keystore::resolver::KeystoreResolver;
use tempfile::TempDir;

#[test]
fn test_keystore_resolver_resolve() {
    let temp_dir = TempDir::new().unwrap();
    let home = Some(temp_dir.path().to_path_buf());

    let keystore_root = KeystoreResolver::resolve(home.as_ref()).unwrap();

    assert!(keystore_root.to_string_lossy().contains("keys"));
}
