// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared artifact text handling for public facade types.
//!
//! Keeps parse/load/save mechanics private while facade modules own domain operations.

use std::path::Path;

use crate::format::content::{FileEncContent, KvEncContent};
use crate::support::fs::atomic::save_text;
use crate::support::fs::load_text_with_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;

pub(super) trait ArtifactContent: Clone {
    fn detect(content: String) -> Result<Self>;
    fn detect_with_source(content: String, source_name: String) -> Result<Self>;
    fn as_str(&self) -> &str;
}

impl ArtifactContent for FileEncContent {
    fn detect(content: String) -> Result<Self> {
        FileEncContent::detect(content)
    }

    fn detect_with_source(content: String, source_name: String) -> Result<Self> {
        FileEncContent::detect_with_source(content, source_name)
    }

    fn as_str(&self) -> &str {
        FileEncContent::as_str(self)
    }
}

impl ArtifactContent for KvEncContent {
    fn detect(content: String) -> Result<Self> {
        KvEncContent::detect(content)
    }

    fn detect_with_source(content: String, source_name: String) -> Result<Self> {
        KvEncContent::detect_with_source(content, source_name)
    }

    fn as_str(&self) -> &str {
        KvEncContent::as_str(self)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ArtifactLoadPolicy {
    max_bytes: usize,
    read_subject: &'static str,
}

impl ArtifactLoadPolicy {
    pub(super) const fn new(max_bytes: usize, read_subject: &'static str) -> Self {
        Self {
            max_bytes,
            read_subject,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ArtifactText<C> {
    content: C,
}

impl<C> ArtifactText<C>
where
    C: ArtifactContent,
{
    pub(super) fn parse(content: impl Into<String>) -> Result<Self> {
        Ok(Self {
            content: C::detect(content.into())?,
        })
    }

    fn parse_with_source(content: String, source_name: String) -> Result<Self> {
        Ok(Self {
            content: C::detect_with_source(content, source_name)?,
        })
    }

    pub(super) fn from_content(content: C) -> Self {
        Self { content }
    }

    pub(super) fn load(path: impl AsRef<Path>, policy: ArtifactLoadPolicy) -> Result<Self> {
        let path = path.as_ref();
        let content = load_text_with_limit(path, policy.max_bytes, policy.read_subject)?;
        Self::parse_with_source(content, format_path_relative_to_cwd(path))
    }

    pub(super) fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        save_text(path.as_ref(), self.as_str())
    }

    pub(super) fn as_str(&self) -> &str {
        self.content.as_str()
    }

    pub(super) fn content(&self) -> &C {
        &self.content
    }
}
