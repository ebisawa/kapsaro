// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Atomic writes to an output path the operator named on the command line.
//! Local state and workspace documents are written fd-relatively instead and never come through here.

use crate::support::fs::ensure_dir;
use crate::support::fs::policy::{enforce_path_not_symlink, is_real_dir};
use crate::support::fs::relative::{
    open_dir_nofollow, optional_child_type_at, save_bytes_at, save_bytes_restricted_at, ChildType,
    DirectoryScope, OpenDir,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
#[cfg(feature = "cli-test-support")]
use serde::Serialize;
use std::path::Path;

/// The directory a write publishes into, or `.` when the path names no parent.
fn target_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Ensure the parent directory exists, by the same rule the write applies.
///
/// The refusal comes first, so a symlinked parent is turned away here with the
/// message the write itself would give rather than passing this check and being
/// rejected a moment later on a different ground. A parent that is already a
/// real directory is left alone; a missing one is created.
fn ensure_parent_dir(path: &Path) -> Result<()> {
    let parent = target_parent(path);
    enforce_parent_not_symlink(parent)?;
    if is_real_dir(parent)? {
        return Ok(());
    }
    ensure_dir(parent)
}

fn enforce_parent_not_symlink(parent: &Path) -> Result<()> {
    enforce_path_not_symlink(parent, |display| {
        format!("refusing to write: parent directory is a symlink: {display}")
    })
}

/// Reach of the entry an output file leaves behind.
///
/// An operator naming an output path decides where it goes, but not who else
/// ends up able to read it. Content that was protected before it was written
/// carries `OwnerOnly` so the umask cannot widen it; anything the workspace
/// already shares keeps the mode the umask produces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SavedFileMode {
    UmaskDefault,
    OwnerOnly,
}

/// Save JSON data atomically (write-then-rename)
/// Crate code persists documents through the restricted-mode helpers, so this
/// plain variant is reached only by the `cli-test-support` harness.
#[cfg(feature = "cli-test-support")]
pub fn save_json<T: Serialize>(path: &Path, data: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(data).map_err(Error::build_json_serialization_error)?;
    save_bytes(path, json.as_bytes())
}

/// Save text content atomically
pub fn save_text(path: &Path, content: &str) -> Result<()> {
    save_bytes(path, content.as_bytes())
}

/// Save bytes atomically, with the mode the umask allows.
pub fn save_bytes(path: &Path, data: &[u8]) -> Result<()> {
    save_bytes_with_mode(path, data, SavedFileMode::UmaskDefault)
}

/// Save text atomically as an entry only its owner can read.
pub fn save_text_restricted(path: &Path, content: &str) -> Result<()> {
    save_bytes_restricted(path, content.as_bytes())
}

/// Save bytes atomically as an entry only its owner can read.
///
/// Decrypted plaintext and an exported private key are secrets the moment they
/// land, and a umask of 022 would publish them to every account on the machine.
/// The mode is pinned rather than left to the umask, because the operator who
/// asked for the file is not the one who chose the umask.
pub fn save_bytes_restricted(path: &Path, data: &[u8]) -> Result<()> {
    save_bytes_with_mode(path, data, SavedFileMode::OwnerOnly)
}

/// Save bytes atomically, with every step bound to one parent descriptor.
///
/// The parent is opened once, refusing a symlink in its final position, and the
/// staging file, its sync, the rename and the directory sync all run against
/// that descriptor. Naming the parent again for each step would let it be
/// replaced in between, and the rename would then land wherever the new entry
/// points.
///
/// An inspection that cannot answer is a refusal, not a pass: a parent whose
/// identity was never established is not known to be safe.
/// Anything but a regular file standing at the target is not something kapsaro
/// wrote, and replacing it would erase the only sign the path was tampered
/// with, so the entry is refused rather than followed or overwritten. The
/// inspection and the rename are two steps, so an entry that appears between
/// them can still be replaced; the rename does not follow a link, so what it
/// replaces is the name and never a file somewhere else.
fn save_bytes_with_mode(path: &Path, data: &[u8], mode: SavedFileMode) -> Result<()> {
    ensure_parent_dir(path)?;
    let name = target_name(path)?;
    let parent = open_target_parent(path)?;
    enforce_replaceable_target(&parent, name, path)?;
    match mode {
        SavedFileMode::UmaskDefault => save_bytes_at(&parent, name, data),
        SavedFileMode::OwnerOnly => save_bytes_restricted_at(&parent, name, data),
    }
}

/// Open the directory that will hold the write, refusing a symlinked parent.
///
/// A symlinked parent is an escape: every later step addresses the entry
/// through this descriptor, so the one thing that must not be followed is the
/// step that produces it.
fn open_target_parent(path: &Path) -> Result<OpenDir> {
    let parent = target_parent(path);
    match open_dir_nofollow(parent, DirectoryScope::Generic) {
        Ok(opened) => Ok(opened),
        Err(error) => Err(name_parent_refusal(parent, error)),
    }
}

/// Say which parent stood in the way, naming a symlink as the write sees it.
///
/// The open refuses a symlink through the entry type it found; the wording the
/// write uses everywhere else is restored here so one rule reads the same
/// whether the parent was checked before the write or bound by it.
fn name_parent_refusal(parent: &Path, error: Error) -> Error {
    if error.kind() != crate::ErrorKind::InvalidOperation {
        return error;
    }
    match enforce_parent_not_symlink(parent) {
        Err(refusal) => refusal,
        Ok(()) => error,
    }
}

/// Refuse a target the write must not replace, on the opened parent.
///
/// A free name and a regular file are the only entries a write publishes over.
/// A symlink sends the content somewhere the operator never named, and a FIFO,
/// socket or device is state some other program is using; renaming over any of
/// them removes it with nothing left to show it was there.
fn enforce_replaceable_target(parent: &OpenDir, name: &str, path: &Path) -> Result<()> {
    let occupied = match optional_child_type_at(parent, name)? {
        None | Some(ChildType::RegularFile) => return Ok(()),
        Some(child_type) => child_type,
    };
    Err(Error::build_invalid_operation_error(format!(
        "refusing to write: target is a {}: {}",
        name_target_type(occupied),
        format_path_relative_to_cwd(path)
    )))
}

/// Name the entry standing where the write expected a regular file or nothing.
fn name_target_type(child_type: ChildType) -> &'static str {
    match child_type {
        ChildType::Symlink => "symlink",
        ChildType::Directory => "directory",
        ChildType::RegularFile => "regular file",
        ChildType::Other => "special file",
    }
}

/// The single component the write publishes inside the opened parent.
///
/// The fd-relative layer this module builds on addresses every entry by
/// `&str`, so a final component that is valid on Unix but not valid UTF-8 is
/// refused rather than passed through. This is unsupported by design: making
/// it work would mean rebuilding the fd-relative layer around `OsStr`.
fn target_name(path: &Path) -> Result<&str> {
    let name = path.file_name().ok_or_else(|| {
        Error::build_invalid_argument_error(format!(
            "refusing to write: the output path has no final component: {}",
            format_path_relative_to_cwd(path)
        ))
    })?;
    name.to_str().ok_or_else(|| {
        Error::build_invalid_argument_error(format!(
            "refusing to write: the output path's final component is not valid UTF-8: {}",
            format_path_relative_to_cwd(path)
        ))
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_atomic_error_test.rs"]
mod support_fs_atomic_error_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_atomic_test.rs"]
mod support_fs_atomic_test;
