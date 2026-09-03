// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Fixed text-artifact review capabilities.
//! Binds raw content and inode identity to the directory used for publication.

use std::path::Path;
use std::sync::Arc;

use crate::support::fs::relative::{self, open_dir_identity, DirectoryFd, OpenDir};
use crate::support::fs::snapshot::TextFileSnapshot;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

/// A text file held open exactly as the operator reviewed it, together with the
/// directory it was reached through.
#[derive(Debug)]
pub(crate) struct ReviewedTextFile {
    snapshot: TextFileSnapshot,
    subject_label: String,
    max_bytes: usize,
}

impl ReviewedTextFile {
    pub(crate) fn load_existing_at(
        dir: Arc<OpenDir>,
        name: &str,
        subject_label: &str,
        max_bytes: usize,
    ) -> Result<Self> {
        let snapshot = TextFileSnapshot::capture_at(dir, name, max_bytes, subject_label)?;
        if snapshot.content().is_none() {
            return Err(Error::build_not_found_error(format!(
                "Failed to read file {}: no such file",
                format_path_relative_to_cwd(snapshot.path())
            )));
        }
        Ok(Self::from_snapshot(snapshot, subject_label, max_bytes))
    }

    pub(crate) fn capture_optional_at(
        dir: Arc<OpenDir>,
        name: &str,
        subject_label: &str,
        max_bytes: usize,
    ) -> Result<Self> {
        let snapshot = TextFileSnapshot::capture_at(dir, name, max_bytes, subject_label)?;
        Ok(Self::from_snapshot(snapshot, subject_label, max_bytes))
    }

    fn from_snapshot(snapshot: TextFileSnapshot, subject_label: &str, max_bytes: usize) -> Self {
        Self {
            snapshot,
            subject_label: subject_label.to_string(),
            max_bytes,
        }
    }

    pub(crate) fn directory(&self) -> &Arc<OpenDir> {
        self.snapshot.directory()
    }

    pub(crate) fn name(&self) -> &str {
        self.snapshot.name()
    }

    pub(crate) fn path(&self) -> &Path {
        self.snapshot.path()
    }

    pub(crate) fn content(&self) -> Option<&str> {
        self.snapshot.content()
    }

    pub(crate) fn require_content(&self) -> Result<&str> {
        self.content().ok_or_else(|| {
            Error::build_invalid_operation_error(format!(
                "{} content is required",
                self.subject_label
            ))
        })
    }

    pub(crate) fn matches_reviewed_state(&self, other: &Self) -> Result<bool> {
        if self.name() != other.name() || self.content() != other.content() {
            return Ok(false);
        }
        Ok(open_dir_identity(self.directory().as_ref())?
            == open_dir_identity(other.directory().as_ref())?)
    }

    fn ensure_bound_directory<D>(&self, dir: &D) -> Result<()>
    where
        D: DirectoryFd,
    {
        if open_dir_identity(self.directory().as_ref())? == open_dir_identity(dir)? {
            return Ok(());
        }
        Err(Error::build_invalid_operation_error(format!(
            "{} was reviewed under another directory and must be reviewed again.",
            self.subject_display()
        )))
    }

    pub(crate) fn ensure_current(&self) -> Result<()> {
        self.snapshot
            .ensure_current(&self.subject_display(), self.max_bytes)
    }

    fn ensure_current_at<D>(&self, dir: &D) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.ensure_bound_directory(dir)?;
        relative::ensure_text_file_content_matches_at(
            dir,
            self.name(),
            self.content(),
            &self.subject_display(),
            self.max_bytes,
        )
    }

    pub(crate) fn ensure_identity_and_content_current_at<D>(&self, dir: &D) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.ensure_current_at(dir)?;
        if self.snapshot.still_holds_in(dir)? {
            return Ok(());
        }
        Err(Error::build_invalid_operation_error(format!(
            "{} changed since review and must be reviewed again.",
            self.subject_display()
        )))
    }

    pub(crate) fn save_replacement_at<D>(&self, dir: &D, content: &str) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.ensure_bound_directory(dir)?;
        relative::save_text_at(dir, self.name(), content)
    }

    #[cfg(test)]
    pub(crate) fn save_replacement_if_current_at<D>(&self, dir: &D, content: &str) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.save_replacement_if_current_with_precondition_at(dir, content, || Ok(()))
    }

    pub(crate) fn save_replacement_if_current_with_precondition_at<D, F>(
        &self,
        dir: &D,
        content: &str,
        precondition: F,
    ) -> Result<()>
    where
        D: DirectoryFd,
        F: FnOnce() -> Result<()>,
    {
        self.ensure_bound_directory(dir)?;
        relative::save_text_at_with_precondition(dir, self.name(), content, || {
            precondition()?;
            self.ensure_identity_and_content_current_at(dir)
        })
    }

    fn subject_display(&self) -> String {
        format!("{} '{}'", self.subject_label, self.path().display())
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_context_review_test.rs"]
mod tests;
