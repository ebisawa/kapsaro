// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Path display contracts for available and unavailable working directories.
//! Exercises fallback formatting without changing the process working directory.

use super::DisplayBase;
use std::path::{Path, PathBuf};

#[test]
fn test_path_display_preserves_locations_with_or_without_a_working_directory() {
    for (name, cwd, path, expected) in [
        ("working directory", Some("/workspace"), "/workspace", "."),
        (
            "child",
            Some("/workspace"),
            "/workspace/key.json",
            "key.json",
        ),
        (
            "outside",
            Some("/workspace"),
            "/other/key.json",
            "/other/key.json",
        ),
        (
            "unavailable cwd",
            None,
            "/workspace/key.json",
            "/workspace/key.json",
        ),
        ("relative fallback", None, "key.json", "key.json"),
    ] {
        let base = DisplayBase {
            cwd: cwd.map(PathBuf::from),
        };
        assert_eq!(base.relative(Path::new(path)), expected, "{name}");
    }
}
