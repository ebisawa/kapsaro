// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for key command
//!
//! Tests for key generation, listing, activation, removal, and export.

mod activate;
mod export;
mod list;
mod new;
mod remove;

/// Helper to find the first kid directory in a member directory
///
/// Returns the kid as a String
fn find_kid_in_member_dir(member_dir: &std::path::Path) -> String {
    use std::fs;
    let kid_dirs: Vec<_> = fs::read_dir(member_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();

    assert_eq!(kid_dirs.len(), 1, "Should have exactly one kid directory");

    kid_dirs[0]
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}
