// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Helper for tests that reach a directory lock from a path.
//! Opens the path once and takes the lock on the descriptor that opened it.

use crate::support::fs::lock::{with_exclusive_locked_directory, ExclusiveLockedDir};
use crate::support::fs::relative::{open_dir_nofollow, DirectoryScope};
use crate::Result;
use std::path::Path;

/// Lock the workspace directory a path names, for a test that has only a path.
///
/// Production takes every directory lock on a descriptor it already holds, so
/// the path is resolved once here and the lock taken on what that open returned.
/// The open refuses a link in the final position, which is the entry a lock must
/// never be taken through.
pub(crate) fn with_locked_workspace_dir<T, F>(dir: &Path, f: F) -> Result<T>
where
    F: FnOnce(&ExclusiveLockedDir<'_>) -> Result<T>,
{
    let opened = open_dir_nofollow(dir, DirectoryScope::Generic)?;
    with_exclusive_locked_directory(&opened, f)
}
