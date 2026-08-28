// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the path display helpers.
//! Covers how a path under, equal to, and outside the working directory renders.

use std::path::Path;

use super::{format_path_relative_to_cwd, path_or_current_dir, DisplayBase};
use crate::test_utils::with_temp_cwd;

/// A path below the working directory renders as the part below it, which is
/// what an operator would type to reach the entry again.
#[test]
fn test_format_path_relative_to_cwd_shortens_a_path_below_the_working_directory() {
    let temp = tempfile::tempdir().unwrap();

    with_temp_cwd(temp.path(), || {
        // Read the directory back rather than reusing the temporary path, which
        // resolves through a symlink on macOS.
        let cwd = std::env::current_dir().unwrap();

        let display = format_path_relative_to_cwd(&cwd.join("keys").join("private.json"));

        assert_eq!(display, "keys/private.json");
    });
}

/// The working directory itself renders as the current directory, so a message
/// built from it always names something the operator can act on.
#[test]
fn test_format_path_relative_to_cwd_names_the_working_directory_itself() {
    let temp = tempfile::tempdir().unwrap();

    with_temp_cwd(temp.path(), || {
        let cwd = std::env::current_dir().unwrap();

        let display = format_path_relative_to_cwd(&cwd);

        assert_eq!(display, ".");
    });
}

/// A path the working directory does not contain keeps its full form, because
/// there is no shorter way to name it.
#[test]
fn test_format_path_relative_to_cwd_keeps_a_path_outside_the_working_directory() {
    let display = format_path_relative_to_cwd(Path::new("/"));

    assert_eq!(display, "/");
}

/// A walk resolves the working directory once and names every finding against
/// it, so a path below the directory the walk started in reads exactly as a
/// single finding would name it.
#[test]
fn test_display_base_shortens_a_path_below_the_directory_it_resolved() {
    let temp = tempfile::tempdir().unwrap();

    with_temp_cwd(temp.path(), || {
        let cwd = std::env::current_dir().unwrap();
        let base = DisplayBase::resolve();

        let display = base.finding(&cwd.join("keys").join("private.json"));

        assert_eq!(display, "keys/private.json");
    });
}

/// An entry name is chosen by whoever can write the directory, so a base spells
/// out a control character in one rather than letting it reach the terminal and
/// forge a second report line.
#[test]
fn test_display_base_spells_out_a_control_character_in_an_entry_name() {
    let base = DisplayBase::resolve();

    let display = base.finding(Path::new("/local/state/first\nSecond forged line"));

    assert_eq!(display, "/local/state/first\\nSecond forged line");
}

/// An ancestor chain runs out of components at the empty path, and the
/// directory that stands for is the one the process is in.
#[test]
fn test_path_or_current_dir_names_the_current_directory_for_an_empty_path() {
    assert_eq!(path_or_current_dir(Path::new("")), Path::new("."));
}

/// A path with components of its own stands for itself.
#[test]
fn test_path_or_current_dir_keeps_a_path_that_names_something() {
    assert_eq!(path_or_current_dir(Path::new("keys")), Path::new("keys"));
}
