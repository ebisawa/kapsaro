// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Fixed file inputs for encryption and trust-authorized reads.
//! Reports global permissions on the opened file and its retained directory chain.

use crate::service::workspace::WorkspaceCreationTarget;
use crate::support::fs::read::{decode_loaded_text, load_capped_bytes, FileReader};
use crate::support::fs::relative::{
    open_dir_following, open_regular_file_following_at, DirectoryScope,
};
use crate::support::limits::MAX_PLAINTEXT_INPUT_SIZE;
use crate::support::path::format_finding_path;
use crate::{Error, Result};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A regular file opened once and retained across all read reviews.
pub struct FileInputTarget {
    file: Arc<File>,
    path: PathBuf,
}

impl FileInputTarget {
    /// Select a file, preserving the regular-file read policy for explicit links.
    pub fn open(path: impl AsRef<Path>, global: Option<&WorkspaceCreationTarget>) -> Result<Self> {
        let path = path.as_ref();
        let name = path
            .file_name()
            .ok_or_else(|| Error::build_invalid_argument_error("Input requires a file name"))?;
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = open_dir_following(parent_path, DirectoryScope::Generic)?;
        let scope = if global
            .map(|global| global.contains_directory(&parent))
            .transpose()?
            .unwrap_or(false)
        {
            DirectoryScope::GlobalWorkspace
        } else {
            DirectoryScope::Generic
        };
        let file = open_regular_file_following_at(&parent.with_scope(scope), name)?;
        Ok(Self {
            file: Arc::new(file),
            path: path.to_path_buf(),
        })
    }

    /// Display path selected by the caller.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn file(&self) -> &Arc<File> {
        &self.file
    }

    pub(crate) fn load_plaintext(&self) -> Result<Vec<u8>> {
        self.load_bytes(MAX_PLAINTEXT_INPUT_SIZE, "Input file")
    }

    pub(crate) fn load_text(&self, limit: usize, subject: &str) -> Result<String> {
        decode_loaded_text(
            self.load_bytes(limit, subject)?,
            &format_finding_path(&self.path),
        )
    }

    fn load_bytes(&self, limit: usize, subject: &str) -> Result<Vec<u8>> {
        let mut reader = FileReader::new(&self.file);
        load_capped_bytes(
            &mut reader,
            limit,
            subject,
            &format_finding_path(&self.path),
        )
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_file_input_test.rs"]
mod service_file_input_test;
