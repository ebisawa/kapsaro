// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/fs/atomic module
//!
//! Tests for atomic file operations.

use crate::support::fs::atomic::{
    save_bytes, save_bytes_restricted, save_json, save_text, save_text_restricted,
};
#[cfg(unix)]
use crate::support::fs::test_umask::{isolated_umask_test, with_umask};
use serde::{Deserialize, Serialize};
use std::fs;
use tempfile::TempDir;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct TestData {
    name: String,
    value: i32,
}

#[test]
fn test_save_json_roundtrip_with_existing_and_missing_parent() {
    for relative in ["test.json", "subdir/test.json"] {
        let home = TempDir::new().unwrap();
        let path = home.path().join(relative);
        let data = TestData {
            name: "test".to_string(),
            value: 42,
        };
        save_json(&path, &data).unwrap();
        let loaded: TestData = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded, data, "{relative}");
        assert!(path.parent().unwrap().is_dir(), "{relative}");
    }
}

#[test]
fn test_save_bytes_roundtrip_with_existing_and_missing_parent() {
    for relative in ["test.bin", "subdir/test.bin"] {
        let home = TempDir::new().unwrap();
        let path = home.path().join(relative);
        save_bytes(&path, b"Binary data").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"Binary data", "{relative}");
    }
}

#[test]
fn test_save_text() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    save_text(&file_path, "Hello, World!").unwrap();

    assert!(file_path.exists());
    let content = fs::read_to_string(&file_path).unwrap();
    assert_eq!(content, "Hello, World!");
}

#[cfg(unix)]
#[test]
fn test_save_text_rejects_symlinked_parent_directory() {
    use std::os::unix::fs::symlink;
    let temp_dir = TempDir::new().unwrap();
    let real_parent = temp_dir.path().join("outside");
    fs::create_dir(&real_parent).unwrap();
    let fake_parent = temp_dir.path().join("secrets");
    symlink(&real_parent, &fake_parent).unwrap();
    let target = fake_parent.join("trapped.txt");

    let error = save_text(&target, "should not land").unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("parent directory is a symlink"),
        "unexpected error: {message}"
    );
    assert!(
        !real_parent.join("trapped.txt").exists(),
        "write must not land in the symlink target"
    );
}

#[cfg(unix)]
#[test]
fn test_save_text_rejects_symlinked_target() {
    use std::os::unix::fs::symlink;
    let temp_dir = TempDir::new().unwrap();
    let real_path = temp_dir.path().join("outside.txt");
    fs::write(&real_path, "original").unwrap();
    let fake_path = temp_dir.path().join("in.txt");
    symlink(&real_path, &fake_path).unwrap();

    let error = save_text(&fake_path, "should not overwrite").unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("target is a symlink"),
        "unexpected error: {message}"
    );
    assert_eq!(
        fs::read_to_string(&real_path).unwrap(),
        "original",
        "write must not have followed the symlink"
    );
}

#[cfg(unix)]
fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

isolated_umask_test! {
    /// Decrypted plaintext is a secret the moment it lands. The mode is pinned
    /// rather than left to the umask, because the operator who asked for the
    /// file is not the one who chose the umask.
    #[cfg(unix)]
    fn test_save_bytes_restricted_pins_0600_under_an_ordinary_umask() {
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("plain.env");

        with_umask(0o022, || {
            save_bytes_restricted(&target, b"SECRET=value\n").unwrap();
        });

        assert_eq!(mode_of(&target), 0o600);
        assert_eq!(fs::read(&target).unwrap(), b"SECRET=value\n");
    }
}

isolated_umask_test! {
    /// An exported private key carries the same rule as decrypted plaintext.
    #[cfg(unix)]
    fn test_save_text_restricted_pins_0600_under_an_ordinary_umask() {
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("portable-key.txt");

        with_umask(0o022, || {
            save_text_restricted(&target, "kapsaro:key:portable").unwrap();
        });

        assert_eq!(mode_of(&target), 0o600);
        assert_eq!(fs::read_to_string(&target).unwrap(), "kapsaro:key:portable");
    }
}

isolated_umask_test! {
    /// An encrypted artifact is shared through git, so it keeps the mode the
    /// checkout expects rather than one only its author can read.
    #[cfg(unix)]
    fn test_save_text_follows_an_ordinary_umask() {
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("secret.env.encrypted");

        with_umask(0o022, || {
            save_text(&target, "{}").unwrap();
        });

        assert_eq!(mode_of(&target), 0o644);
    }
}

/// The write goes through a temporary file that is renamed into place. A
/// leftover temporary means the sequence was interrupted or reordered.
#[test]
fn test_save_bytes_leaves_only_the_target_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("payload.bin");

    save_bytes(&file_path, b"content").unwrap();

    let entries: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("payload.bin")]);
}

/// A FIFO standing at the output path is not something kapsaro wrote, and the
/// rename that publishes a write would remove it without a trace. Only a free
/// name and a regular file are replaced.
#[cfg(unix)]
#[test]
fn test_save_text_rejects_a_fifo_at_the_target() {
    let temp_dir = TempDir::new().unwrap();
    let target = temp_dir.path().join("pipe");
    make_fifo(&target);

    let error = save_text(&target, "content").expect_err("a FIFO must not be replaced by a write");
    let message = error.format_user_message();

    assert!(
        message.contains("target is a special file"),
        "the refusal names what stands there: {message}"
    );
    assert!(
        std::os::unix::fs::FileTypeExt::is_fifo(
            &fs::symlink_metadata(&target)
                .expect("the FIFO is still there")
                .file_type()
        ),
        "the write must leave the FIFO in place"
    );
}

/// A directory standing at the output path is refused for the same reason.
#[cfg(unix)]
#[test]
fn test_save_text_rejects_a_directory_at_the_target() {
    let temp_dir = TempDir::new().unwrap();
    let target = temp_dir.path().join("occupied");
    fs::create_dir(&target).unwrap();

    let error =
        save_text(&target, "content").expect_err("a directory must not be replaced by a write");
    let message = error.format_user_message();

    assert!(
        message.contains("target is a directory"),
        "the refusal names what stands there: {message}"
    );
}

#[cfg(unix)]
fn make_fifo(path: &std::path::Path) {
    // Made by the POSIX utility rather than a binding: `mkfifo(2)` has no safe
    // wrapper in the crate's dependencies, and the workspace forbids `unsafe`.
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("mkfifo can be run");
    assert!(status.success(), "mkfifo failed for {}", path.display());
}
