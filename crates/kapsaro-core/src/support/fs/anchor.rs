// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Cloneable root-directory capability for a local state or workspace root.
//! Creates missing paths fd-relatively and binds the root to the descriptor it opened.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::relative::{
    ensure_scoped_child_dir_at, open_child_dir, open_child_dir_following, open_dir_following,
    DirectoryFd, DirectoryScope, OpenDir,
};
use crate::error::absent_as_none;
#[cfg(unix)]
use crate::support::fs::permission::{
    report_local_state_ancestor_safety, report_scoped_open_permission,
};
// A root path is spelled by the operator and its final component may be an entry
// somebody else created, so every message that names one goes through
// `format_finding_path`; a raw display would let a name carry control characters
// straight into the terminal.
use crate::support::path::format_finding_path;
use crate::{Error, ErrorKind, Result};

#[derive(Debug, Clone)]
pub(crate) struct AnchoredDir {
    parent: Option<Arc<OpenDir>>,
    opened: Arc<OpenDir>,
}

impl AnchoredDir {
    pub(crate) fn open(
        path: impl Into<PathBuf>,
        scope: DirectoryScope,
        subject: &str,
    ) -> Result<Self> {
        let path = path.into();
        #[cfg(unix)]
        report_ancestor_safety(&path, scope);
        let (parent, opened) = open_bound_directory(&path, scope)
            .map_err(|error| with_subject(error, scope, subject, &path))?;
        // A bare open reports nothing about the root's own permissions: a
        // command that only enumerates what it holds never touches a document,
        // and one that does reads or writes through a permission chain that
        // already covers this directory (`document_store`, the keystore's
        // per-key chains, the trust store's own chain). Reporting here as well
        // would only warn a command that never needed to know.
        Ok(Self {
            parent: parent.map(Arc::new),
            opened: Arc::new(opened),
        })
    }

    /// Open a root a command is built to run without.
    ///
    /// A root that does not exist yet is absence rather than a failure, while an
    /// unsafe path or an I/O failure keeps its own error: a command must not
    /// fall back to its no-root behaviour because the directory could not be
    /// inspected.
    pub(crate) fn open_optional(
        path: impl Into<PathBuf>,
        scope: DirectoryScope,
        subject: &str,
    ) -> Result<Option<Self>> {
        absent_as_none(Self::open(path, scope, subject))
    }

    pub(crate) fn create(
        path: impl Into<PathBuf>,
        scope: DirectoryScope,
        subject: &str,
    ) -> Result<Self> {
        let path = path.into();
        // Checked before the missing components are created, so the walk sees
        // the directories that were already there rather than the ones this
        // call is about to make.
        #[cfg(unix)]
        report_ancestor_safety(&path, scope);
        let (parent, opened) = match fs::symlink_metadata(&path) {
            Ok(_) => open_existing_root(&path, scope, subject)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_final_directory(&path, scope, subject)?
            }
            Err(error) => {
                return Err(Error::build_io_error_with_source(
                    format!(
                        "Failed to inspect {subject}: {}",
                        format_finding_path(&path)
                    ),
                    error,
                ));
            }
        };
        Ok(Self {
            parent: parent.map(Arc::new),
            opened: Arc::new(opened),
        })
    }

    pub(crate) fn ensure_child(&self, name: &str) -> Result<Self> {
        let opened = ensure_scoped_child_dir_at(self, name)?;
        Ok(Self {
            parent: Some(self.opened.clone()),
            opened: Arc::new(opened),
        })
    }

    pub(crate) fn open_child(&self, name: &str) -> Result<Self> {
        let opened = open_child_dir(self, name)?;
        // See `open`'s note: a bare open reports nothing here either, for the
        // same reason. A caller that reads or writes through this child reaches
        // its own permission chain, which covers this directory too.
        Ok(Self {
            parent: Some(self.opened.clone()),
            opened: Arc::new(opened),
        })
    }

    pub(crate) fn parent(&self) -> Option<&OpenDir> {
        self.parent.as_deref()
    }
}

impl DirectoryFd for AnchoredDir {
    fn file(&self) -> &fs::File {
        self.opened.file()
    }

    fn path(&self) -> &Path {
        self.opened.path()
    }

    fn scope(&self) -> DirectoryScope {
        self.opened.scope()
    }
}

/// Audit the directories leading to a local state root.
///
/// A workspace lives inside a repository the operator shares on purpose, so the
/// owner-only expectations that guard local state would only produce findings
/// about a layout that is working as intended.
#[cfg(unix)]
fn report_ancestor_safety(path: &Path, scope: DirectoryScope) {
    if scope == DirectoryScope::LocalState {
        report_local_state_ancestor_safety(path);
    }
}

fn open_existing_root(
    path: &Path,
    scope: DirectoryScope,
    subject: &str,
) -> Result<(Option<OpenDir>, OpenDir)> {
    let (parent, opened) = open_bound_directory(path, scope)
        .map_err(|error| with_subject(error, scope, subject, path))?;
    #[cfg(unix)]
    report_scoped_open_permission(&opened, opened.file(), opened.path());
    Ok((parent, opened))
}

/// Create the missing components of a root path and open the last one.
///
/// The path is probed twice, so a concurrent first run can create it in
/// between. That leaves nothing missing, which is a race to absorb by opening
/// what is now there rather than a corrupt tree to report.
fn create_final_directory(
    path: &Path,
    scope: DirectoryScope,
    subject: &str,
) -> Result<(Option<OpenDir>, OpenDir)> {
    run_before_ancestor_search_hook();
    let (ancestor_path, missing_names) = find_existing_ancestor(path, scope, subject)?;
    let Some((final_name, leading_names)) = missing_names.split_last() else {
        return open_existing_root(path, scope, subject);
    };
    let mut parent = open_dir_following(&ancestor_path, scope)?;
    for name in leading_names {
        parent = ensure_scoped_child_dir_at(&parent, name)?;
    }
    let opened = ensure_scoped_child_dir_at(&parent, final_name)?;
    Ok((Some(parent), opened))
}

fn find_existing_ancestor(
    path: &Path,
    scope: DirectoryScope,
    subject: &str,
) -> Result<(PathBuf, Vec<String>)> {
    let mut current = path.to_path_buf();
    let mut missing_names = Vec::new();
    loop {
        match fs::metadata(&current) {
            Ok(_) => {
                missing_names.reverse();
                return Ok((current, missing_names));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let (parent, name) = required_parent_and_name(&current, scope, subject)?;
                missing_names.push(name.to_string());
                current = parent.to_path_buf();
            }
            Err(error) => return Err(inspect_create_path_error(subject, &current, error)),
        }
    }
}

fn required_parent_and_name<'a>(
    path: &'a Path,
    scope: DirectoryScope,
    subject: &str,
) -> Result<(&'a Path, &'a str)> {
    let (parent, name) = parent_and_name(path).ok_or_else(|| {
        Error::build_invalid_argument_error(format!(
            "{subject} must have a final path component: {}",
            format_finding_path(path)
        ))
    })?;
    let name = name
        .to_str()
        .ok_or_else(|| non_utf8_created_component_error(path, scope))?;
    Ok((parent, name))
}

fn inspect_create_path_error(subject: &str, path: &Path, error: std::io::Error) -> Error {
    Error::build_io_error_with_source(
        format!(
            "Failed to inspect {subject} path: {}",
            format_finding_path(path)
        ),
        error,
    )
}

/// Open the root a path names, following it when it is a symlink.
///
/// Pointing the root at a directory on another volume is a deliberate setup,
/// so the link is resolved rather than refused. The identity the caller keeps
/// is the descriptor, which stays on the directory that was opened even if the
/// link is repointed afterwards.
fn open_bound_directory(path: &Path, scope: DirectoryScope) -> Result<(Option<OpenDir>, OpenDir)> {
    let Some((parent_path, name)) = parent_and_name(path) else {
        return open_dir_following(path, scope).map(|opened| (None, opened));
    };
    let parent = open_dir_following(parent_path, scope)?;
    let opened = open_child_dir_following(&parent, name)?;
    Ok((Some(parent), opened))
}

/// The directory a path sits in and the name it occupies there.
///
/// The name is handed back as the bytes the path holds. A root and the
/// directories above it are named by the operator and the OS, and a Unix path
/// component is a byte string: requiring one to decode as UTF-8 would refuse a
/// directory that is perfectly ordinary on the machine it lives on. The names
/// kapsaro chooses itself are a different matter and keep their own rule.
fn parent_and_name(path: &Path) -> Option<(&Path, &OsStr)> {
    let name = path.file_name()?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Some((parent, name))
}

/// Refuse a component kapsaro is about to create whose name does not decode.
///
/// A component that has to be created is one every later operation addresses by
/// name through the `&str` API the rest of the tree is reached by, so it has to
/// be text. An existing directory is only opened, and reaching it never needs
/// the name to decode.
fn non_utf8_created_component_error(path: &Path, scope: DirectoryScope) -> Error {
    let message = format!(
        "refusing to create a path component whose name is not UTF-8: {}",
        format_finding_path(path)
    );
    match scope {
        DirectoryScope::LocalState => Error::build_local_state_path_unsafe_error(message),
        DirectoryScope::Generic => Error::build_invalid_operation_error(message),
    }
}

// Test-only seam: runs once right before the ancestor search begins, so a
// test can simulate a concurrent process finishing the whole tree first and
// check the walk absorbs it by opening what is now there instead of trying to
// create a directory that already exists. Compiled out of production builds.
#[cfg(test)]
thread_local! {
    static BEFORE_ANCESTOR_SEARCH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Arm an action that runs right before the next ancestor search begins.
#[cfg(test)]
pub(crate) fn run_before_ancestor_search(action: impl FnOnce() + 'static) {
    BEFORE_ANCESTOR_SEARCH.with(|slot| *slot.borrow_mut() = Some(Box::new(action)));
}

#[cfg(test)]
fn run_before_ancestor_search_hook() {
    if let Some(action) = BEFORE_ANCESTOR_SEARCH.with(|slot| slot.borrow_mut().take()) {
        action();
    }
}

#[cfg(not(test))]
fn run_before_ancestor_search_hook() {}

fn with_subject(error: Error, scope: DirectoryScope, subject: &str, path: &Path) -> Error {
    match error.kind() {
        ErrorKind::NotFound => Error::build_not_found_error(format!(
            "{subject} does not exist: {}",
            format_finding_path(path)
        )),
        ErrorKind::InvalidOperation => {
            let message = format!(
                "Failed to open {subject} '{}': {}",
                format_finding_path(path),
                error.format_user_message()
            );
            match scope {
                DirectoryScope::LocalState => Error::build_local_state_path_unsafe_error(message),
                DirectoryScope::Generic => Error::build_invalid_operation_error(message),
            }
        }
        _ => error,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_anchor_test.rs"]
mod support_fs_anchor_test;
