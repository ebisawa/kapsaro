// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/fs module.

use crate::support::fs::read::load_bytes_with_limit;
use crate::support::fs::snapshot::TextFileSnapshot;
use crate::support::fs::{ensure_dir, load_bytes, load_text_with_limit};
use crate::support::limits::MAX_PLAINTEXT_INPUT_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_load_text_with_limit() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    fs::write(&file_path, "hello").unwrap();

    let content = load_text_with_limit(&file_path, 5, "test file").unwrap();

    assert_eq!(content, "hello");
}

#[test]
fn test_load_text_with_limit_rejects_oversized_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("oversized.txt");
    fs::write(&file_path, "hello!").unwrap();

    let error = load_text_with_limit(&file_path, 5, "test file").unwrap_err();

    let message = error.to_string();
    assert!(message.contains("exceeds maximum size limit"));
    assert!(message.contains("test file"));
}

#[test]
fn test_ensure_dir() {
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().join("a/b/c");

    ensure_dir(&dir_path).unwrap();

    assert!(dir_path.exists());
    assert!(dir_path.is_dir());
}

#[cfg(unix)]
#[test]
fn test_ensure_dir_rejects_symlinked_ancestor() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let real_parent = temp_dir.path().join("outside");
    let linked_parent = temp_dir.path().join("linked");
    fs::create_dir(&real_parent).unwrap();
    symlink(&real_parent, &linked_parent).unwrap();

    let error = ensure_dir(&linked_parent.join("nested")).unwrap_err();

    let message = error.to_string();
    assert!(message.contains("symlink"), "unexpected error: {message}");
    assert!(
        !real_parent.join("nested").exists(),
        "directory creation must not follow a symlinked ancestor"
    );
}

#[cfg(unix)]
#[test]
fn test_load_text_with_limit_reads_symlink() {
    use std::os::unix::fs::symlink;
    let temp_dir = TempDir::new().unwrap();
    let real_path = temp_dir.path().join("real.txt");
    fs::write(&real_path, "hello").unwrap();
    let link_path = temp_dir.path().join("link.txt");
    symlink(&real_path, &link_path).unwrap();

    let content = load_text_with_limit(&link_path, 64, "test file").unwrap();

    assert_eq!(content, "hello");
}

#[cfg(unix)]
fn create_fifo(path: &std::path::Path) {
    use std::ffi::CString;

    let c_path = CString::new(path.to_str().unwrap()).unwrap();
    // mkfifo has no safe wrapper. The path is a valid CString inside a
    // temporary directory this test owns.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed");
}

#[cfg(unix)]
#[test]
fn test_load_bytes_with_limit_rejects_fifo() {
    let temp_dir = TempDir::new().unwrap();
    let fifo_path = temp_dir.path().join("pipe");
    create_fifo(&fifo_path);

    let error = load_bytes_with_limit(&fifo_path, 64, "test file").unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("refusing to read non-regular file"),
        "unexpected error: {message}"
    );
}

#[test]
fn test_load_bytes_reads_an_input_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("secret.env");
    fs::write(&file_path, b"SECRET=value\n").unwrap();

    let bytes = load_bytes(&file_path).unwrap();

    assert_eq!(bytes, b"SECRET=value\n");
}

/// An input path comes from a command-line argument, so nothing bounds what
/// stands there. A plaintext past the bound could never be read back out of the
/// document it would produce, so it is refused before it is held in memory.
#[test]
fn test_load_bytes_rejects_an_input_past_the_plaintext_bound() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("oversized.bin");
    fs::write(&file_path, vec![0_u8; MAX_PLAINTEXT_INPUT_SIZE + 1]).unwrap();

    let error = load_bytes(&file_path).unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("exceeds maximum size limit"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("Input file"),
        "unexpected error: {message}"
    );
}

/// A FIFO named where an input file was expected would otherwise hand the
/// command an unbounded stream and no end to wait for.
#[cfg(unix)]
#[test]
fn test_load_bytes_rejects_a_non_regular_input() {
    let temp_dir = TempDir::new().unwrap();
    let fifo_path = temp_dir.path().join("pipe");
    create_fifo(&fifo_path);

    let error = load_bytes(&fifo_path).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("refusing to read non-regular file"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_load_bytes_with_limit_caps_streaming_read() {
    // A file whose metadata reports a small size but whose content is larger
    // than the cap must still be rejected (streaming cap via Read::take).
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("big.bin");
    let body: Vec<u8> = (0..256u16).flat_map(|i| [i as u8; 64]).collect();
    fs::write(&file_path, &body).unwrap();

    let error = load_bytes_with_limit(&file_path, 128, "capped read").unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("exceeds maximum size limit"),
        "unexpected error: {message}"
    );
    assert!(message.contains("capped read"));
}

/// The read stops one byte past the limit, so the size the file really has never
/// reaches the message. Naming the limit is what tells the operator how far the
/// file has to come down.
#[test]
fn test_load_bytes_with_limit_names_the_limit_the_file_went_past() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("oversized.bin");
    fs::write(&file_path, vec![b'x'; 42]).unwrap();

    let error = load_bytes_with_limit(&file_path, 32, "test file").unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("test file exceeds maximum size limit (32 bytes)"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains(&format_path_relative_to_cwd(&file_path)),
        "unexpected error: {message}"
    );
}

const REVIEWED: &str = "Reviewed file";

/// A snapshot is addressed to a directory descriptor, so a test binds the
/// directory the way a command does before capturing what it holds.
#[cfg(unix)]
fn open_dir(path: &std::path::Path) -> std::sync::Arc<crate::support::fs::relative::OpenDir> {
    use crate::support::fs::relative::{open_dir_nofollow, DirectoryScope};

    std::sync::Arc::new(open_dir_nofollow(path, DirectoryScope::Generic).unwrap())
}

#[cfg(unix)]
#[test]
fn test_text_file_snapshot_accepts_a_file_that_did_not_change() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("reviewed.txt");
    fs::write(&file_path, "same content").unwrap();

    let snapshot =
        TextFileSnapshot::capture_at(open_dir(temp_dir.path()), "reviewed.txt", 64, REVIEWED)
            .unwrap();

    assert_eq!(snapshot.content(), Some("same content"));
    assert_eq!(snapshot.path(), file_path);
    snapshot.ensure_current(REVIEWED, 64).unwrap();
}

#[cfg(unix)]
#[test]
fn test_text_file_snapshot_accepts_an_absence_that_persists() {
    let temp_dir = TempDir::new().unwrap();

    let snapshot =
        TextFileSnapshot::capture_at(open_dir(temp_dir.path()), "missing.txt", 64, REVIEWED)
            .unwrap();

    assert_eq!(snapshot.content(), None);
    snapshot.ensure_current(REVIEWED, 64).unwrap();
}

#[cfg(unix)]
#[test]
fn test_text_file_snapshot_rejects_a_file_created_after_review() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("reviewed.txt");
    let snapshot =
        TextFileSnapshot::capture_at(open_dir(temp_dir.path()), "reviewed.txt", 64, REVIEWED)
            .unwrap();

    fs::write(&file_path, "created after review").unwrap();

    let error = snapshot.ensure_current(REVIEWED, 64).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Reviewed file changed since review"),
        "unexpected error: {error}"
    );
}

#[cfg(unix)]
#[test]
fn test_text_file_snapshot_rejects_a_file_rewritten_in_place() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("reviewed.txt");
    fs::write(&file_path, "old content").unwrap();
    let snapshot =
        TextFileSnapshot::capture_at(open_dir(temp_dir.path()), "reviewed.txt", 64, REVIEWED)
            .unwrap();

    fs::write(&file_path, "changed content").unwrap();

    let error = snapshot.ensure_current(REVIEWED, 64).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Reviewed file changed since review"),
        "unexpected error: {error}"
    );
}

/// Content alone cannot say whether the file about to be acted on is the file
/// that was read. Replacing it with an identical copy swaps the inode behind
/// the name, and the bytes that arrive on a re-read were never reviewed.
#[cfg(unix)]
#[test]
fn test_text_file_snapshot_rejects_a_replacement_holding_the_same_bytes() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("reviewed.txt");
    fs::write(&file_path, "same content").unwrap();
    let snapshot =
        TextFileSnapshot::capture_at(open_dir(temp_dir.path()), "reviewed.txt", 64, REVIEWED)
            .unwrap();

    let replacement = temp_dir.path().join("reviewed.txt.new");
    fs::write(&replacement, "same content").unwrap();
    fs::rename(&replacement, &file_path).unwrap();

    let error = snapshot.ensure_current(REVIEWED, 64).unwrap_err();
    assert!(
        error.to_string().contains("must be reviewed again"),
        "unexpected error: {error}"
    );
}

#[cfg(unix)]
#[test]
fn test_text_file_snapshot_rejects_an_oversized_file() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("reviewed.txt"), "abcdef").unwrap();

    let error =
        TextFileSnapshot::capture_at(open_dir(temp_dir.path()), "reviewed.txt", 5, REVIEWED)
            .unwrap_err();

    assert!(
        error.to_string().contains("exceeds maximum size limit"),
        "unexpected error: {error}"
    );
}

/// A reviewed document is a regular file. A link standing where one is expected
/// sends the read outside the directory the snapshot is bound to, so it is
/// refused rather than followed.
#[cfg(unix)]
#[test]
fn test_text_file_snapshot_refuses_a_symlinked_entry() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let real_path = temp_dir.path().join("real.txt");
    fs::write(&real_path, "same content").unwrap();
    symlink(&real_path, temp_dir.path().join("reviewed.txt")).unwrap();

    let error =
        TextFileSnapshot::capture_at(open_dir(temp_dir.path()), "reviewed.txt", 64, REVIEWED)
            .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("refusing to read non-regular file"),
        "unexpected error: {error}"
    );
}

/// A dangling link is an entry, so a reviewed absence no longer holds once a
/// name appears, whatever it points at.
#[cfg(unix)]
#[test]
fn test_text_file_snapshot_rejects_a_dangling_link_created_after_review() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("reviewed.txt");
    let snapshot =
        TextFileSnapshot::capture_at(open_dir(temp_dir.path()), "reviewed.txt", 64, REVIEWED)
            .unwrap();

    symlink(temp_dir.path().join("gone"), &file_path).unwrap();

    snapshot.ensure_current(REVIEWED, 64).unwrap_err();
}

/// The re-check goes through the directory descriptor the review read from, so
/// a directory path repointed at another tree does not get to answer for the
/// file that was reviewed.
#[cfg(unix)]
#[test]
fn test_text_file_snapshot_answers_from_the_directory_it_captured() {
    let temp_dir = TempDir::new().unwrap();
    let reviewed_dir = temp_dir.path().join("reviewed");
    let substitute_dir = temp_dir.path().join("substitute");
    fs::create_dir(&reviewed_dir).unwrap();
    fs::create_dir(&substitute_dir).unwrap();
    fs::write(reviewed_dir.join("doc.txt"), "reviewed content").unwrap();
    fs::write(substitute_dir.join("doc.txt"), "other content").unwrap();

    let snapshot =
        TextFileSnapshot::capture_at(open_dir(&reviewed_dir), "doc.txt", 64, REVIEWED).unwrap();
    fs::rename(&reviewed_dir, temp_dir.path().join("moved-aside")).unwrap();
    fs::rename(&substitute_dir, &reviewed_dir).unwrap();

    assert_eq!(snapshot.content(), Some("reviewed content"));
    snapshot.ensure_current(REVIEWED, 64).unwrap();
}
