// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared local state document loading and atomic saving.
//! Warns about any document whose ancestry or file is reachable by group or other.

use crate::support::fs::permission::{collect_open_permission_violations, report_violations};
use crate::support::fs::relative::{self, DirectoryFd};
use crate::support::path::format_finding_path;
use crate::{Error, Result};
use serde::Serialize;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug)]
pub(crate) struct LoadedDocument<T> {
    pub(crate) document: T,
    /// Serialized bytes as they were read, kept only where a caller needs to
    /// pin the exact reviewed content. Private key documents never retain it.
    pub(crate) raw_content: Option<String>,
}

/// Whether the serialized source text survives past parsing.
///
/// Discarding wipes the buffer that is still held, because key documents pass
/// through this loader. The wipe is best effort: the read grows its buffer as it
/// goes, and copies left in freed heap by an earlier reallocation are beyond
/// reach here.
#[derive(Clone, Copy, Eq, PartialEq)]
enum RawContentRetention {
    Retain,
    Discard,
}

impl RawContentRetention {
    fn apply(self, mut content: String) -> Option<String> {
        match self {
            Self::Retain => Some(content),
            Self::Discard => {
                content.zeroize();
                None
            }
        }
    }
}

/// Load a document and discard its source text.
pub(crate) fn load_required_at<D, T>(
    dir: &D,
    path: &Path,
    permission_chain: &[&dyn DirectoryFd],
    max_size: usize,
    subject: &str,
    parse: impl FnOnce(&str) -> Result<T>,
) -> Result<LoadedDocument<T>>
where
    D: DirectoryFd,
{
    load_at_with_retention(
        dir,
        path,
        permission_chain,
        max_size,
        subject,
        parse,
        RawContentRetention::Discard,
    )
}

/// Load a document and keep its source text so a caller can pin the exact
/// bytes it reviewed. Never use this for documents holding private keys.
pub(crate) fn load_required_with_raw_at<D, T>(
    dir: &D,
    path: &Path,
    permission_chain: &[&dyn DirectoryFd],
    max_size: usize,
    subject: &str,
    parse: impl FnOnce(&str) -> Result<T>,
) -> Result<LoadedDocument<T>>
where
    D: DirectoryFd,
{
    load_at_with_retention(
        dir,
        path,
        permission_chain,
        max_size,
        subject,
        parse,
        RawContentRetention::Retain,
    )
}

/// Inspect the whole ancestry in one pass, then read and parse the document.
///
/// Every directory of the chain is reported together so the operator sees each
/// entry that has to be repaired. The document file carries its own permission
/// report, raised by the read that opens it.
fn load_at_with_retention<D, T>(
    dir: &D,
    path: &Path,
    permission_chain: &[&dyn DirectoryFd],
    max_size: usize,
    subject: &str,
    parse: impl FnOnce(&str) -> Result<T>,
    retention: RawContentRetention,
) -> Result<LoadedDocument<T>>
where
    D: DirectoryFd,
{
    report_violations(collect_open_permission_violations(permission_chain));
    let content = relative::load_text_with_limit_at(dir, file_name(path)?, max_size, subject)?;
    let parsed = parse(&content);
    let raw_content = retention.apply(content);
    let document = parsed?;
    Ok(LoadedDocument {
        document,
        raw_content,
    })
}

pub(crate) fn load_optional_at<D, T>(
    dir: &D,
    path: &Path,
    permission_chain: &[&dyn DirectoryFd],
    max_size: usize,
    subject: &str,
    parse: impl FnOnce(&str) -> Result<T>,
) -> Result<Option<LoadedDocument<T>>>
where
    D: DirectoryFd,
{
    if !document_exists_with_inspected_ancestry(dir, path, permission_chain)? {
        return Ok(None);
    }
    load_required_at(dir, path, permission_chain, max_size, subject, parse).map(Some)
}

/// Optional twin of `load_required_with_raw_at`.
pub(crate) fn load_optional_with_raw_at<D, T>(
    dir: &D,
    path: &Path,
    permission_chain: &[&dyn DirectoryFd],
    max_size: usize,
    subject: &str,
    parse: impl FnOnce(&str) -> Result<T>,
) -> Result<Option<LoadedDocument<T>>>
where
    D: DirectoryFd,
{
    if !document_exists_with_inspected_ancestry(dir, path, permission_chain)? {
        return Ok(None);
    }
    load_required_with_raw_at(dir, path, permission_chain, max_size, subject, parse).map(Some)
}

/// Whether the document is there, inspecting the ancestry it is reached through
/// either way.
///
/// The permission rule covers the directories a document is reached through as
/// well as the document itself, and those directories are reused by every
/// command whether or not the optional document standing in them exists.
/// Inspecting only when the read goes ahead would leave a local state root that
/// group or other can reach unreported for as long as the document is absent.
///
/// The repeat this adds to a read that does go ahead costs nothing: the warning
/// sink holds one entry per finding, so the same directory reported twice in one
/// command is recorded once.
fn document_exists_with_inspected_ancestry<D>(
    dir: &D,
    path: &Path,
    permission_chain: &[&dyn DirectoryFd],
) -> Result<bool>
where
    D: DirectoryFd,
{
    report_violations(collect_open_permission_violations(permission_chain));
    relative::file_exists_at(dir, file_name(path)?)
}

/// Serialize a document and publish it under `name`, owner-only.
///
/// The serialized text is wiped before it is dropped, matching the wipe the
/// loading path performs. Like that one it is best effort: serde grows its
/// buffer as it writes, and a copy left in a freed allocation is out of reach.
pub(crate) fn save_json_restricted_at<D, T>(dir: &D, name: &str, document: &T) -> Result<()>
where
    D: DirectoryFd,
    T: Serialize,
{
    let json = Zeroizing::new(
        serde_json::to_string_pretty(document).map_err(Error::build_json_serialization_error)?,
    );
    relative::save_text_restricted_at(dir, name, &json)
}

/// The entry name a document path resolves to.
///
/// Every write is relative to an opened directory, so only the last component
/// reaches the filesystem; the rest of the path is what a caller reports.
///
/// The path is named through the finding formatter, because whoever can write a
/// directory chooses the names in it and a control character in one would
/// otherwise reach the operator's terminal as the message is printed.
pub(super) fn file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::build_config_error(format!(
                "Invalid document path '{}'",
                format_finding_path(path)
            ))
        })
}

#[cfg(test)]
#[path = "../../tests/unit/internal/io_document_store_test.rs"]
mod io_document_store_test;
