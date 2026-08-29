// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File snapshot capture and change detection helpers.
//! Supports review-to-execution consistency checks for filesystem operations.

#[cfg(unix)]
use std::fmt;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
#[cfg(unix)]
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

#[cfg(unix)]
use super::read::{decode_loaded_text, load_capped_bytes};
use super::relative::DirectoryFd;
#[cfg(unix)]
use super::relative::{file_exists_at, open_regular_file_at, OpenDir};

/// A regular file held open with the identity and metadata reviewed by the caller.
#[cfg(unix)]
pub(crate) struct RegularFileSnapshot {
    file: File,
    identity: FileIdentity,
    metadata: FileMetadata,
    raw_bytes: Vec<u8>,
}

#[cfg(unix)]
impl fmt::Debug for RegularFileSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegularFileSnapshot")
            .field("file", &self.file)
            .field("identity", &self.identity)
            .field("metadata", &self.metadata)
            .field("raw_bytes", &format_args!("{} bytes", self.raw_bytes.len()))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(unix)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(unix)]
struct FileMetadata {
    mode: u32,
    links: u64,
    owner: u32,
    group: u32,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
pub(crate) fn load_optional_regular_file_snapshot_at<D>(
    dir: &D,
    name: &str,
) -> Result<Option<RegularFileSnapshot>>
where
    D: DirectoryFd,
{
    if !file_exists_at(dir, name)? {
        return Ok(None);
    }
    let file = open_regular_file_at(dir, name)?;
    let path = dir.path().join(name);
    let raw_bytes = load_snapshot_bytes(&file, &path)?;
    let metadata = load_file_metadata(&file, &path)?;
    Ok(Some(RegularFileSnapshot {
        file,
        identity: FileIdentity::from(&metadata),
        metadata: FileMetadata::from(&metadata),
        raw_bytes,
    }))
}

/// Confirm the entry still is what was reviewed, and hand back what proves it.
///
/// The confirmed entry is returned rather than dropped: a caller that goes on
/// to delete the document unlinks it by name, and the name can be pointing at a
/// different inode by then. Returning the descriptor lets the caller re-check
/// the identity it just accepted against the entry it is about to remove.
#[cfg(unix)]
pub(crate) fn ensure_regular_file_matches_snapshot_at<D>(
    dir: &D,
    name: &str,
    reviewed: Option<&RegularFileSnapshot>,
    subject_display: &str,
) -> Result<Option<RegularFileSnapshot>>
where
    D: DirectoryFd,
{
    let current = load_optional_regular_file_snapshot_at(dir, name)?;
    let matches = match (reviewed, current.as_ref()) {
        (None, None) => true,
        (Some(reviewed), Some(current)) => reviewed.matches(current)?,
        _ => false,
    };
    if matches {
        return Ok(current);
    }
    Err(Error::build_invalid_operation_error(format!(
        "{} changed since reset confirmation and must be reviewed again.",
        subject_display
    )))
}

#[cfg(unix)]
impl RegularFileSnapshot {
    fn matches(&self, current: &Self) -> Result<bool> {
        let held_metadata = load_file_metadata(&self.file, Path::new("reviewed file"))?;
        let held_bytes = load_snapshot_bytes(&self.file, Path::new("reviewed file"))?;
        Ok(self.identity == FileIdentity::from(&held_metadata)
            && self.metadata == FileMetadata::from(&held_metadata)
            && self.raw_bytes == held_bytes
            && self.identity == current.identity
            && self.metadata == current.metadata
            && self.raw_bytes == current.raw_bytes)
    }

    /// Whether the name still resolves to the inode and bytes this snapshot holds.
    ///
    /// Checked from the descriptor rather than the path, so a name repointed or
    /// an open inode rewritten after confirmation is reported instead of acted on.
    pub(crate) fn still_holds<D>(&self, dir: &D, name: &str) -> Result<bool>
    where
        D: DirectoryFd,
    {
        let Some(current) = load_optional_regular_file_snapshot_at(dir, name)? else {
            return Ok(false);
        };
        let held = load_file_metadata(&self.file, Path::new("reviewed file"))?;
        let held_bytes = load_snapshot_bytes(&self.file, Path::new("reviewed file"))?;
        Ok(self.identity == FileIdentity::from(&held)
            && self.raw_bytes == held_bytes
            && self.identity == current.identity
            && self.raw_bytes == current.raw_bytes)
    }
}

#[cfg(unix)]
fn load_snapshot_bytes(file: &File, path: &Path) -> Result<Vec<u8>> {
    let mut reader = file.try_clone().map_err(|error| {
        Error::build_io_error_with_source(
            format!("Failed to read file {}: {}", path.display(), error),
            error,
        )
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|error| {
        Error::build_io_error_with_source(
            format!("Failed to read file {}: {}", path.display(), error),
            error,
        )
    })?;
    load_capped_bytes(
        &mut reader,
        MAX_JSON_DOCUMENT_READ_SIZE,
        "Reviewed document",
        &format_path_relative_to_cwd(path),
    )
}

#[cfg(unix)]
impl From<&std::fs::Metadata> for FileIdentity {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(unix)]
impl From<&std::fs::Metadata> for FileMetadata {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            mode: metadata.mode(),
            links: metadata.nlink(),
            owner: metadata.uid(),
            group: metadata.gid(),
            length: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[cfg(unix)]
fn load_file_metadata(file: &File, path: &Path) -> Result<std::fs::Metadata> {
    file.metadata().map_err(|error| {
        Error::build_io_error_with_source(
            format!("Failed to inspect file {}: {}", path.display(), error),
            error,
        )
    })
}

/// A text file held open, together with the directory it was reached through.
///
/// The reviewed content on its own cannot say whether the file about to be
/// acted on is the file that was read: opening the same name again can reach a
/// different inode, and the content that arrives then was never reviewed. The
/// descriptor from review time is kept, and the check compares identity,
/// metadata and bytes against it rather than re-reading a path and trusting it.
///
/// The directory descriptor is kept for the same reason one step further out: a
/// re-read addressed by path would answer from whichever tree the path names by
/// then, so every question this snapshot answers goes through the directory the
/// review actually read from.
#[cfg(unix)]
#[derive(Debug)]
pub struct TextFileSnapshot {
    dir: Arc<OpenDir>,
    name: String,
    path: PathBuf,
    reviewed: Option<ReviewedText>,
}

#[cfg(unix)]
#[derive(Debug)]
struct ReviewedText {
    file: File,
    identity: FileIdentity,
    metadata: FileMetadata,
    content: String,
}

#[cfg(unix)]
impl TextFileSnapshot {
    /// Read the entry `name` holds below `dir` and keep both of them open.
    ///
    /// A name with nothing under it captures an absence, which is as much a part
    /// of what was reviewed as any content: an entry that appears afterwards was
    /// never seen.
    pub fn capture_at(
        dir: Arc<OpenDir>,
        name: &str,
        max_bytes: usize,
        subject: &str,
    ) -> Result<Self> {
        let path = dir.path().join(name);
        let reviewed = if file_exists_at(dir.as_ref(), name)? {
            Some(read_reviewed_text(
                dir.as_ref(),
                name,
                max_bytes,
                subject,
                &path,
            )?)
        } else {
            None
        };
        Ok(Self {
            dir,
            name: name.to_string(),
            path,
            reviewed,
        })
    }

    pub fn directory(&self) -> &Arc<OpenDir> {
        &self.dir
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn content(&self) -> Option<&str> {
        self.reviewed
            .as_ref()
            .map(|reviewed| reviewed.content.as_str())
    }

    /// Refuse to go on when the file is no longer the one that was reviewed.
    pub fn ensure_current(&self, subject_display: &str, max_bytes: usize) -> Result<()> {
        if self.still_current(subject_display, max_bytes)? {
            return Ok(());
        }
        Err(Error::build_invalid_operation_error(format!(
            "{} changed since review and must be reviewed again.",
            subject_display
        )))
    }

    /// Whether the reviewed name under `dir` still resolves to the very inode
    /// that was read.
    ///
    /// Answered from the descriptor captured at review time and a fresh lookup
    /// of the name, so a name repointed at another file since then is reported
    /// instead of being compared byte for byte and passing.
    ///
    /// A review that captured an absence has no inode to bind to, and the
    /// absence itself is what the content comparison already checks, so nothing
    /// is claimed here.
    pub fn still_holds_in<D>(&self, dir: &D) -> Result<bool>
    where
        D: DirectoryFd,
    {
        let Some(reviewed) = self.reviewed.as_ref() else {
            return Ok(true);
        };
        let held = load_file_metadata(&reviewed.file, Path::new("reviewed file"))?;
        if reviewed.identity != FileIdentity::from(&held) {
            return Ok(false);
        }
        let Some(current) = load_optional_regular_file_snapshot_at(dir, &self.name)? else {
            return Ok(false);
        };
        Ok(reviewed.identity == current.identity)
    }

    /// Whether the entry is still what it was, down to the bytes.
    ///
    /// The content is compared as well as the identity and the metadata: an
    /// in-place overwrite of the same length, landing inside the timestamp
    /// granularity the filesystem records, changes nothing else the snapshot
    /// holds. The reviewed text is already in memory, so this costs no read of
    /// its own beyond the one the re-capture makes anyway.
    fn still_current(&self, subject: &str, max_bytes: usize) -> Result<bool> {
        let Some(reviewed) = self.reviewed.as_ref() else {
            // A dangling link is an entry, so the question is whether a name
            // appeared at all rather than whether one resolves.
            return Ok(!file_exists_at(self.dir.as_ref(), &self.name)?);
        };
        let held = load_file_metadata(&reviewed.file, Path::new("reviewed file"))?;
        if reviewed.identity != FileIdentity::from(&held)
            || reviewed.metadata != FileMetadata::from(&held)
        {
            return Ok(false);
        }
        let current = Self::capture_at(Arc::clone(&self.dir), &self.name, max_bytes, subject)?;
        let Some(current) = current.reviewed else {
            return Ok(false);
        };
        Ok(reviewed.identity == current.identity
            && reviewed.metadata == current.metadata
            && reviewed.content == current.content)
    }
}

/// Open the entry `name` holds below `dir` and read it under a cap.
///
/// The open refuses a symlink in the final position: a reviewed document is a
/// regular file, and a link standing in for it sends the read somewhere the
/// directory descriptor was never bound to. What the review rests on is the
/// descriptor returned here, which stays on the inode it opened however the
/// name moves afterwards.
#[cfg(unix)]
fn read_reviewed_text<D>(
    dir: &D,
    name: &str,
    max_bytes: usize,
    subject: &str,
    path: &Path,
) -> Result<ReviewedText>
where
    D: DirectoryFd,
{
    let display = format_path_relative_to_cwd(path);
    let mut file = open_regular_file_at(dir, name)?;
    let bytes = load_capped_bytes(&mut file, max_bytes, subject, &display)?;
    let content = decode_loaded_text(bytes, &display)?;
    let metadata = load_file_metadata(&file, path)?;
    Ok(ReviewedText {
        identity: FileIdentity::from(&metadata),
        metadata: FileMetadata::from(&metadata),
        content,
        file,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_snapshot_test.rs"]
mod support_fs_snapshot_test;
