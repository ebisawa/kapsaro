// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Directory creation policy for paths addressed by name.
//! Creates the missing components of a tree on a chain of descriptors and refuses to build one through a symlink.

use std::fs;
use std::path::{Path, PathBuf};

use crate::support::path::{format_path_relative_to_cwd, path_or_current_dir};
use crate::{Error, Result};

use super::relative::{ensure_child_dir_at, open_dir_nofollow, DirectoryScope};

/// Which wording a refusal about a directory is phrased in.
///
/// This selects nothing but message text. Every directory made here is created
/// the same way and with the same mode; what differs is only whether the
/// operator is told about a directory or about a workspace path.
#[derive(Debug, Clone, Copy)]
pub(crate) enum DirectoryKind {
    General,
    Workspace,
}

/// Whether the path names a directory rather than a link or another entry type.
///
/// An inspection that could not answer is an error rather than a `false`.
/// Collapsing a denied lookup into "there is no directory here" would send the
/// caller on to create one, and the creation would then fail for a reason that
/// no longer names what actually went wrong. A workspace search reading this
/// answer stops on such an error instead of carrying on to the directory above,
/// which is what keeps a lookup it was not allowed to make from being read as
/// "no workspace stands here".
pub(crate) fn is_real_dir(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        // The final component is not followed, so a link to a directory answers
        // as the link it is rather than as the directory it names.
        Ok(metadata) => Ok(metadata.file_type().is_dir()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(inspect_directory_error(path, error)),
    }
}

/// Create every missing component of `path`, each one below the last.
///
/// The deepest existing ancestor is opened once and every level after it is
/// made and reopened relative to the descriptor above it. Creating each level
/// by full path instead would re-resolve the ones already made, so a component
/// replaced by a symlink between two steps would carry the rest of the tree
/// wherever it points.
pub(crate) fn ensure_real_directory_tree(path: &Path, kind: DirectoryKind) -> Result<()> {
    let (ancestor, missing) = split_at_existing_ancestor(path, kind)?;
    if missing.is_empty() {
        return Ok(());
    }
    let mut parent = open_dir_nofollow(&ancestor, DirectoryScope::Generic)
        .map_err(|error| creation_root_error(&ancestor, error, kind))?;
    for name in missing {
        parent = ensure_child_dir_at(&parent, &name)?;
        run_after_level_created();
    }
    Ok(())
}

// Test-only seam: runs once after a level has been made, so a test can move
// that level aside and check the next one still lands below the descriptor the
// walk holds. Compiled out of production builds.
#[cfg(test)]
thread_local! {
    static AFTER_LEVEL_CREATED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Arm an action that runs right after the next directory level is created.
///
/// A racing process can replace a level between its creation and the next
/// step, and only a call point inside the creation loop can open that window,
/// so the seam is armed from here and fires from production control flow.
#[cfg(test)]
pub(crate) fn run_after_next_level_created(action: impl FnOnce() + 'static) {
    AFTER_LEVEL_CREATED.with(|slot| *slot.borrow_mut() = Some(Box::new(action)));
}

#[cfg(test)]
fn run_after_level_created() {
    if let Some(action) = AFTER_LEVEL_CREATED.with(|slot| slot.borrow_mut().take()) {
        action();
    }
}

#[cfg(not(test))]
fn run_after_level_created() {}

pub(crate) fn enforce_path_not_symlink(
    path: &Path,
    message: impl FnOnce(String) -> String,
) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(
            Error::build_invalid_operation_error(message(format_path_relative_to_cwd(path))),
        ),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(inspect_directory_error(path, e)),
    }
}

/// Split the path into the deepest directory that exists and what is missing
/// below it, outermost missing name first.
fn split_at_existing_ancestor(path: &Path, kind: DirectoryKind) -> Result<(PathBuf, Vec<String>)> {
    let mut missing = Vec::new();

    for ancestor in path.ancestors() {
        let candidate = path_or_current_dir(ancestor);
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                validate_real_directory(candidate, &metadata, kind)?;
                missing.reverse();
                return Ok((candidate.to_path_buf(), missing));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(required_component(candidate, kind)?);
            }
            Err(e) => return Err(inspect_directory_error(candidate, e)),
        }
    }

    Err(resolve_directory_error(path, kind))
}

/// The final component of a path, as a name a directory-relative create accepts.
fn required_component(path: &Path, kind: DirectoryKind) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| resolve_directory_error(path, kind))
}

fn validate_real_directory(
    path: &Path,
    metadata: &fs::Metadata,
    kind: DirectoryKind,
) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::build_invalid_operation_error(
            symlink_directory_message(path, kind),
        ));
    }
    if !file_type.is_dir() {
        return Err(Error::build_io_error(non_directory_message(path)));
    }
    Ok(())
}

fn inspect_directory_error(path: &Path, e: std::io::Error) -> Error {
    Error::build_io_error_with_source(
        format!(
            "Failed to inspect directory {}: {}",
            format_path_relative_to_cwd(path),
            e
        ),
        e,
    )
}

/// Report a deepest existing ancestor that could not be bound to a descriptor.
fn creation_root_error(path: &Path, error: Error, kind: DirectoryKind) -> Error {
    if error.kind() == crate::ErrorKind::InvalidOperation {
        return Error::build_invalid_operation_error(symlink_directory_message(path, kind));
    }
    error
}

fn resolve_directory_error(path: &Path, kind: DirectoryKind) -> Error {
    let path_display = format_path_relative_to_cwd(path);
    let message = match kind {
        DirectoryKind::General => {
            format!("Failed to resolve directory ancestry for {}", path_display)
        }
        DirectoryKind::Workspace => {
            format!(
                "Failed to resolve workspace directory ancestry for {}",
                path_display
            )
        }
    };
    Error::build_io_error(message)
}

fn symlink_directory_message(path: &Path, kind: DirectoryKind) -> String {
    let path_display = format_path_relative_to_cwd(path);
    match kind {
        DirectoryKind::General => {
            format!(
                "refusing to create directory through symlink: {}",
                path_display
            )
        }
        DirectoryKind::Workspace => {
            format!(
                "refusing to create workspace path through symlink: {}",
                path_display
            )
        }
    }
}

fn non_directory_message(path: &Path) -> String {
    format!(
        "Failed to create directory {}: existing path is not a directory",
        format_path_relative_to_cwd(path)
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_policy_test.rs"]
mod support_fs_policy_test;
