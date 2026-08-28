// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Reading member documents out of a workspace.
//! Every read is addressed relative to the directory descriptor that holds the document.

use super::super::paths::{
    has_member_document_extension, member_file_name, members_dir, open_member_document_parent,
    open_optional_members_dir, open_optional_members_dir_at, MemberStatus,
};
use crate::format::schema::document::parse_public_key_str;
use crate::model::public_key::PublicKey;
use crate::support::fs::relative::{self, ChildType, DirectoryFd, OpenDir};
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// The member document entries a directory holds, in name order, with the type
/// the scan saw for each.
///
/// The types come from the same walk that produced the names, so a caller
/// judges an entry on what the scan saw rather than on a second lookup that
/// could reach a different entry.
fn scan_member_document_entries_at<D>(dir: &D) -> Result<Vec<(String, ChildType)>>
where
    D: DirectoryFd,
{
    let scanned = relative::scan_child_entries_at(dir, relative::ScanBudget::Unlimited)?;
    select_member_document_entries(scanned.entries)
}

/// Keep the entries a scan saw that are spelled the way a member document is.
///
/// A name that does not decode is left out before the extension is judged: it
/// cannot carry that spelling, and ending the listing over one such entry would
/// let an unrelated file dropped into the directory hide every member the
/// workspace has. An entry that does carry the spelling and could not be
/// inspected ends the listing, because it may be a document.
fn select_member_document_entries(
    children: Vec<relative::ScannedChild>,
) -> Result<Vec<(String, ChildType)>> {
    let mut entries = Vec::new();
    for child in children {
        let Some(name) = child.name().decoded().map(str::to_string) else {
            continue;
        };
        if !has_member_document_extension(&name) {
            continue;
        }
        match child {
            relative::ScannedChild::Inspected { child_type, .. } => {
                entries.push((name, child_type))
            }
            relative::ScannedChild::Unreadable { error, .. } => return Err(error),
        }
    }
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    Ok(entries)
}

/// The member document names a directory holds, in name order.
///
/// A `.json` entry of another type fails the listing rather than dropping out
/// of it. The member set a recipient list is derived from is read through here,
/// and passing over an occupied name would hand back a smaller set as though it
/// were the whole one.
pub(crate) fn load_member_document_names_at<D>(dir: &D) -> Result<Vec<String>>
where
    D: DirectoryFd,
{
    scan_member_document_entries_at(dir)?
        .into_iter()
        .map(|(name, child_type)| match child_type {
            ChildType::RegularFile => Ok(name),
            _ => Err(relative::non_regular_file_error(dir, &name)),
        })
        .collect()
}

/// The member document names a directory holds, in name order, whatever type
/// each entry turned out to be.
///
/// A caller that judges every name on its own keeps the entries that are not
/// regular files: reading one fails, and the failure is then reported against
/// that entry instead of ending the listing for every other name beside it.
fn list_member_document_entry_names_at<D>(dir: &D) -> Result<Vec<String>>
where
    D: DirectoryFd,
{
    Ok(scan_member_document_entries_at(dir)?
        .into_iter()
        .map(|(name, _)| name)
        .collect())
}

/// The member documents a status directory holds, sorted by subject handle.
///
/// A directory that is not there yields nothing: a workspace without an
/// incoming/ directory has no incoming members, which is a state to report
/// rather than a failure.
pub(crate) fn load_sorted_members(
    workspace_path: &Path,
    status: MemberStatus,
) -> Result<Vec<PublicKey>> {
    let Some(dir) = open_optional_members_dir(workspace_path, status)? else {
        return Ok(Vec::new());
    };
    load_sorted_members_in_dir(&dir)
}

/// The member documents a status directory holds under one workspace descriptor.
fn load_sorted_members_at<D>(workspace: &D, status: MemberStatus) -> Result<Vec<PublicKey>>
where
    D: DirectoryFd,
{
    let Some(dir) = open_optional_members_dir_at(workspace, status)? else {
        return Ok(Vec::new());
    };
    load_sorted_members_in_dir(&dir)
}

fn load_sorted_members_in_dir<D>(dir: &D) -> Result<Vec<PublicKey>>
where
    D: DirectoryFd,
{
    let mut members = load_member_document_names_at(dir)?
        .into_iter()
        .map(|name| load_verified_member_file_at(dir, &name))
        .collect::<Result<Vec<_>>>()?;
    members.sort_by(|a, b| a.protected.subject_handle.cmp(&b.protected.subject_handle));
    Ok(members)
}

fn list_member_paths(workspace_path: &Path, status: MemberStatus) -> Result<Vec<PathBuf>> {
    let Some(dir) = open_optional_members_dir(workspace_path, status)? else {
        return Ok(Vec::new());
    };
    let base = members_dir(workspace_path, status);
    Ok(load_member_document_names_at(&dir)?
        .into_iter()
        .map(|name| base.join(name))
        .collect())
}

pub fn load_active_member_files(workspace_path: &Path) -> Result<Vec<PublicKey>> {
    load_sorted_members(workspace_path, MemberStatus::Active)
}

/// The member documents one status directory holds, with the descriptor they
/// are read through.
///
/// A caller that judges each document on its own needs the failures apart, so
/// the names are handed over unread and every read is addressed relative to the
/// descriptor this listing was taken from. An entry that is not a regular file
/// is among them: the read of such a name fails and is reported against that
/// name, which tells an operator more than a listing that stops at it. A status
/// directory that is not there holds no documents rather than failing: a
/// workspace without an incoming/ directory has no incoming members, which is a
/// state to report.
pub(crate) struct MemberDocuments {
    dir: Option<OpenDir>,
    names: Vec<String>,
    dir_path: PathBuf,
}

impl MemberDocuments {
    /// The document names the directory holds, in name order.
    pub(crate) fn names(&self) -> &[String] {
        &self.names
    }

    /// Where the status directory stands, for a finding that names it.
    pub(crate) fn dir_path(&self) -> &Path {
        &self.dir_path
    }

    /// Where one document stands, for a finding that names the file.
    pub(crate) fn document_path(&self, name: &str) -> PathBuf {
        self.dir_path.join(name)
    }

    /// Read one document through the descriptor this listing came from.
    pub(crate) fn load(&self, name: &str) -> Result<PublicKey> {
        load_member_file_at(self.require_dir()?, name)
    }

    /// Read one document through that descriptor, keeping the bytes it parsed
    /// from and requiring that its name is the handle it carries.
    ///
    /// A caller that stores what it reviewed needs both halves out of the one
    /// read: reading the name a second time for the bytes would store a document
    /// nobody looked at.
    pub(crate) fn load_verified_document(&self, name: &str) -> Result<LoadedMemberDocument> {
        load_verified_member_document_at(self.require_dir()?, name)
    }

    fn require_dir(&self) -> Result<&OpenDir> {
        self.dir.as_ref().ok_or_else(|| {
            Error::build_not_found_error(format!(
                "Member directory is not present: {}",
                format_path_relative_to_cwd(&self.dir_path)
            ))
        })
    }
}

/// List the member documents one status directory holds, under one workspace
/// descriptor.
pub(crate) fn open_member_documents_at<D>(
    workspace: &D,
    status: MemberStatus,
) -> Result<MemberDocuments>
where
    D: DirectoryFd,
{
    let dir_path = members_dir(workspace.path(), status);
    let Some(dir) = open_optional_members_dir_at(workspace, status)? else {
        return Ok(MemberDocuments {
            dir: None,
            names: Vec::new(),
            dir_path,
        });
    };
    let names = list_member_document_entry_names_at(&dir)?;
    Ok(MemberDocuments {
        dir: Some(dir),
        names,
        dir_path,
    })
}

/// The active member documents held under one workspace descriptor.
///
/// A command that already bound its workspace reads the member set through that
/// descriptor, so the tree it authorizes against is the tree it started in even
/// if the workspace path is repointed while it runs.
pub(crate) fn load_active_member_files_at<D>(workspace: &D) -> Result<Vec<PublicKey>>
where
    D: DirectoryFd,
{
    load_sorted_members_at(workspace, MemberStatus::Active)
}

pub fn list_active_member_paths(workspace_path: &Path) -> Result<Vec<PathBuf>> {
    list_member_paths(workspace_path, MemberStatus::Active)
}

pub fn list_incoming_member_paths(workspace_path: &Path) -> Result<Vec<PathBuf>> {
    list_member_paths(workspace_path, MemberStatus::Incoming)
}

/// Load the document for one member, reporting which directory holds it.
pub fn load_member_file(
    workspace_path: &Path,
    member_handle: &str,
) -> Result<(PublicKey, MemberStatus)> {
    let file_name = member_file_name(member_handle);
    for status in [MemberStatus::Active, MemberStatus::Incoming] {
        let Some(dir) = open_optional_members_dir(workspace_path, status)? else {
            continue;
        };
        if !relative::regular_file_exists_at(&dir, &file_name)? {
            continue;
        }
        return Ok((load_verified_member_file_at(&dir, &file_name)?, status));
    }

    Err(Error::build_not_found_error(format!(
        "Member '{}' not found in workspace",
        member_handle
    )))
}

pub fn load_member_file_from_path(path: &Path) -> Result<PublicKey> {
    let (dir, name) = open_member_document_parent(path)?;
    load_member_file_at(&dir, &name)
}

/// A member document as one read of it saw the entry.
///
/// The bytes and the key they parsed to come from the same read, so a caller
/// that reviews the key and then stores the bytes stores what it reviewed. Two
/// reads of the same name can reach two documents, and only one of them would
/// have been looked at.
#[derive(Debug, Clone)]
pub(crate) struct LoadedMemberDocument {
    pub(crate) content: String,
    pub(crate) public_key: PublicKey,
}

/// Read one member document, keeping the bytes it was parsed from.
pub(crate) fn load_member_document_at<D>(dir: &D, name: &str) -> Result<LoadedMemberDocument>
where
    D: DirectoryFd,
{
    let source_path = dir.path().join(name);
    let source_name = format_path_relative_to_cwd(&source_path);
    let content = relative::load_text_with_limit_at(
        dir,
        name,
        MAX_JSON_DOCUMENT_READ_SIZE,
        "PublicKey file",
    )?;
    run_post_member_document_read_hook();
    let public_key = parse_public_key_str(&content, &source_name)?;
    Ok(LoadedMemberDocument {
        content,
        public_key,
    })
}

pub(crate) fn load_member_file_at<D>(dir: &D, name: &str) -> Result<PublicKey>
where
    D: DirectoryFd,
{
    Ok(load_member_document_at(dir, name)?.public_key)
}

pub fn load_verified_member_file_from_path(path: &Path) -> Result<PublicKey> {
    let (dir, name) = open_member_document_parent(path)?;
    load_verified_member_file_at(&dir, &name)
}

/// Read a member document and require that its name matches the subject handle.
pub(crate) fn load_verified_member_document_at<D>(
    dir: &D,
    name: &str,
) -> Result<LoadedMemberDocument>
where
    D: DirectoryFd,
{
    let document = load_member_document_at(dir, name)?;
    ensure_member_document_stem_matches(dir, name, &document.public_key)?;
    Ok(document)
}

/// Load a member document and require that its name matches the subject handle.
///
/// A loader that derives the current member set, or the default recipient list,
/// from what is on disk has to reject a mismatch here. Otherwise a change that
/// only edits `alice.json` could put bob's key into the recipient set. Loaders
/// bound to one member handle route through here for the same reason.
pub(crate) fn load_verified_member_file_at<D>(dir: &D, name: &str) -> Result<PublicKey>
where
    D: DirectoryFd,
{
    Ok(load_verified_member_document_at(dir, name)?.public_key)
}

/// Require that a document's name is the subject handle it carries.
fn ensure_member_document_stem_matches<D>(dir: &D, name: &str, public_key: &PublicKey) -> Result<()>
where
    D: DirectoryFd,
{
    let stem = Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            Error::build_invalid_argument_error(format!(
                "Member file has no readable stem: {}",
                format_path_relative_to_cwd(&dir.path().join(name))
            ))
        })?;
    if stem != public_key.protected.subject_handle {
        return Err(Error::build_invalid_argument_error(format!(
            "Member handle mismatch: file '{}' contains '{}'",
            stem, public_key.protected.subject_handle
        )));
    }
    Ok(())
}

// Fault-injection seam: runs once a member document has been read and before the
// caller is handed what it read, which is the only window in which the entry a
// caller is about to review can be replaced under it. Only a call point in the
// production read reaches that window, so the seam lives here and compiles out
// of production builds.
#[cfg(test)]
thread_local! {
    static POST_MEMBER_DOCUMENT_READ_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_post_member_document_read_hook() {
    POST_MEMBER_DOCUMENT_READ_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_post_member_document_read_hook() {}

#[cfg(test)]
pub(crate) fn set_post_member_document_read_hook(hook: impl FnOnce() + 'static) {
    POST_MEMBER_DOCUMENT_READ_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/io_workspace_members_load_test.rs"]
mod io_workspace_members_load_test;
