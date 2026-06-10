// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/fs/lock module
//!
//! Tests for file locking utilities.

use crate::support::fs::lock::with_file_lock;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

use crate::test_utils::with_temp_cwd;

#[test]
fn test_with_file_lock() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let result = with_file_lock(&file_path, || {
        fs::write(&file_path, "locked content").unwrap();
        Ok(())
    });

    assert!(result.is_ok());
    assert!(file_path.exists());
    let content = fs::read_to_string(&file_path).unwrap();
    assert_eq!(content, "locked content");
}

#[test]
fn test_with_file_lock_returns_value() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let result = with_file_lock(&file_path, || Ok::<i32, kapsaro_core::Error>(42));

    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_with_file_lock_propagates_error() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let result: Result<(), kapsaro_core::Error> = with_file_lock(&file_path, || {
        Err(kapsaro_core::Error::build_config_error(
            "Test error".to_string(),
        ))
    });

    assert!(result.is_err());
}

#[test]
fn test_with_file_lock_creates_parent_dir() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("a/b/test.txt");
    let parent_dir = file_path.parent().unwrap();

    assert!(
        !parent_dir.exists(),
        "Precondition: parent dir must not exist"
    );

    let result = with_file_lock(&file_path, || {
        // If with_file_lock doesn't create the parent directory, this write
        // will fail and the test will catch it.
        fs::write(&file_path, "locked content").unwrap();
        Ok::<(), kapsaro_core::Error>(())
    });

    assert!(result.is_ok());
    assert!(parent_dir.exists());
    assert!(file_path.exists());
}

#[cfg(unix)]
#[test]
fn test_lock_file_created_with_0600() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.toml");

    with_file_lock(&file_path, || {
        let lock_path = temp_dir.path().join(".test.toml.lock");
        assert!(lock_path.exists());
        let mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        Ok(())
    })
    .unwrap();
}

#[cfg(unix)]
#[test]
fn test_with_file_lock_rejects_symlinked_lock_file() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("config.toml");
    let victim_path = temp_dir.path().join("victim.txt");
    let lock_path = temp_dir.path().join(".config.toml.lock");
    fs::write(&victim_path, "original").unwrap();
    symlink(&victim_path, &lock_path).unwrap();

    let error = with_file_lock(&file_path, || Ok::<(), kapsaro_core::Error>(())).unwrap_err();

    let message = error.to_string();
    assert!(message.contains("symlink"), "unexpected error: {message}");
    assert_eq!(fs::read_to_string(&victim_path).unwrap(), "original");
}

#[cfg(unix)]
#[test]
fn test_with_file_lock_rejects_symlinked_lock_parent() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let real_parent = temp_dir.path().join("outside");
    let fake_parent = temp_dir.path().join("linked");
    fs::create_dir(&real_parent).unwrap();
    symlink(&real_parent, &fake_parent).unwrap();
    let file_path = fake_parent.join("config.toml");

    let error = with_file_lock(&file_path, || Ok::<(), kapsaro_core::Error>(())).unwrap_err();

    let message = error.to_string();
    assert!(message.contains("symlink"), "unexpected error: {message}");
    assert!(
        !real_parent.join(".config.toml.lock").exists(),
        "lock file must not be created outside the intended directory"
    );
}

#[test]
fn test_with_file_lock_accepts_relative_filename_in_current_directory() {
    let temp_dir = TempDir::new().unwrap();

    with_temp_cwd(temp_dir.path(), || {
        let result = with_file_lock(Path::new("relative.txt"), || {
            fs::write("relative.txt", "locked content").unwrap();
            Ok::<(), kapsaro_core::Error>(())
        });

        assert!(result.is_ok());
        assert!(temp_dir.path().join("relative.txt").exists());
        assert!(temp_dir.path().join(".relative.txt.lock").exists());
    });
}
