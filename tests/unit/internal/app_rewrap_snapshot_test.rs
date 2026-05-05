// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use tempfile::TempDir;

#[test]
fn test_promote_accepted_incoming_members_empty_is_noop() {
    let temp_dir = TempDir::new().unwrap();

    let promoted = super::promote_accepted_incoming_members(temp_dir.path(), &[]).unwrap();

    assert!(promoted.is_empty());
}
