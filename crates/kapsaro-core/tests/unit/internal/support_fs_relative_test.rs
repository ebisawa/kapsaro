// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for directory-fd-relative filesystem helpers.
//! Covers child-name validation and symlink-safe read/write/remove.

use super::{
    file_exists_at, list_child_names_at, load_text_with_limit_at, remove_file_at, save_text_at,
    save_text_restricted_at,
};
use crate::support::fs::lock::with_locked_dir;
#[cfg(unix)]
use crate::support::fs::test_umask::{
    run_current_test_in_isolated_umask_process, with_restrictive_umask,
};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[test]
fn test_relative_read_and_write_roundtrip() {
    let temp_dir = TempDir::new().unwrap();

    with_locked_dir(temp_dir.path(), |dir| {
        save_text_at(dir, "data.txt", "hello")?;
        let content = load_text_with_limit_at(dir, "data.txt", 16, "test file")?;

        assert_eq!(content, "hello");
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_relative_list_child_names_returns_sorted_entries() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("b.txt"), "b").unwrap();
    fs::write(temp_dir.path().join("a.txt"), "a").unwrap();

    let names = with_locked_dir(temp_dir.path(), |dir| list_child_names_at(dir)).unwrap();

    assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
}

#[test]
fn test_relative_helpers_reject_nested_name() {
    let temp_dir = TempDir::new().unwrap();

    let error = with_locked_dir(temp_dir.path(), |dir| {
        save_text_at(dir, "../escaped.txt", "payload")
    })
    .unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("single path component"),
        "unexpected error: {message}"
    );
}

#[cfg(unix)]
#[test]
fn test_relative_read_rejects_symlink() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let outside = temp_dir.path().join("outside.txt");
    fs::write(&outside, "secret").unwrap();
    symlink(&outside, temp_dir.path().join("link.txt")).unwrap();

    let error = with_locked_dir(temp_dir.path(), |dir| {
        load_text_with_limit_at(dir, "link.txt", 16, "test file").map(|_| ())
    })
    .unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("refusing to read symlink"),
        "unexpected error: {message}"
    );
}

#[cfg(unix)]
#[test]
fn test_relative_read_rejects_fifo_without_blocking() {
    use std::ffi::CString;

    let temp_dir = TempDir::new().unwrap();
    let fifo_path = temp_dir.path().join("pipe");
    let c_path = CString::new(fifo_path.to_str().unwrap()).unwrap();
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed");

    let error = with_locked_dir(temp_dir.path(), |dir| {
        load_text_with_limit_at(dir, "pipe", 16, "test file").map(|_| ())
    })
    .unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("refusing to read non-regular file"),
        "unexpected error: {message}"
    );
}

#[cfg(unix)]
#[test]
fn test_relative_save_rejects_existing_symlink_target() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let outside = temp_dir.path().join("outside.txt");
    fs::write(&outside, "original").unwrap();
    symlink(&outside, temp_dir.path().join("link.txt")).unwrap();

    let error = with_locked_dir(temp_dir.path(), |dir| {
        save_text_at(dir, "link.txt", "changed")
    })
    .unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("target is a symlink"),
        "unexpected error: {message}"
    );
    assert_eq!(fs::read_to_string(&outside).unwrap(), "original");
}

#[cfg(unix)]
#[test]
fn test_relative_save_stays_on_opened_directory_after_path_swap() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let locked_path = temp_dir.path().join("locked");
    let renamed_path = temp_dir.path().join("locked.real");
    let outside_dir = temp_dir.path().join("outside");
    fs::create_dir(&locked_path).unwrap();
    fs::create_dir(&outside_dir).unwrap();

    with_locked_dir(&locked_path, |dir| {
        fs::rename(&locked_path, &renamed_path).unwrap();
        symlink(&outside_dir, &locked_path).unwrap();
        save_text_at(dir, "data.txt", "payload")
    })
    .unwrap();

    assert_eq!(
        fs::read_to_string(renamed_path.join("data.txt")).unwrap(),
        "payload"
    );
    assert!(
        !outside_dir.join("data.txt").exists(),
        "fd-relative write must not follow the replaced path"
    );
}

#[cfg(unix)]
#[test]
fn test_relative_restricted_save_preserves_0600_with_restrictive_umask() {
    const CHILD_ENV: &str = "KAPSARO_SUPPORT_RELATIVE_UMASK_CHILD";
    const TEST_NAME: &str = "support::fs::relative::support_fs_relative_test::test_relative_restricted_save_preserves_0600_with_restrictive_umask";
    if run_current_test_in_isolated_umask_process(CHILD_ENV, TEST_NAME) {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let target = temp_dir.path().join("secret.txt");

    with_restrictive_umask(|| {
        with_locked_dir(temp_dir.path(), |dir| {
            save_text_restricted_at(dir, "secret.txt", "payload")
        })
        .unwrap();
    });

    let mode = fs::metadata(target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn test_relative_remove_deletes_only_locked_directory_entry() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("data.txt"), "payload").unwrap();

    with_locked_dir(temp_dir.path(), |dir| {
        assert!(file_exists_at(dir, "data.txt")?);
        remove_file_at(dir, "data.txt")?;
        assert!(!file_exists_at(dir, "data.txt")?);
        Ok(())
    })
    .unwrap();
}
