// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared artifact text handling for public facade types.
//!
//! Keeps parse/load/save mechanics private while facade modules own domain operations.

use std::path::Path;

use crate::format::content::{FileEncContent, KvEncContent};
use crate::support::fs::atomic::save_text;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::Result;

pub(super) trait ArtifactContent: Clone {
    fn detect(content: String) -> Result<Self>;
    fn as_str(&self) -> &str;
}

impl ArtifactContent for FileEncContent {
    fn detect(content: String) -> Result<Self> {
        FileEncContent::detect(content)
    }

    fn as_str(&self) -> &str {
        FileEncContent::as_str(self)
    }
}

impl ArtifactContent for KvEncContent {
    fn detect(content: String) -> Result<Self> {
        KvEncContent::detect(content)
    }

    fn as_str(&self) -> &str {
        KvEncContent::as_str(self)
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

    pub(super) fn from_content(content: C) -> Self {
        Self { content }
    }

    pub(super) fn load(path: impl AsRef<Path>, label: &str) -> Result<Self> {
        let content = load_text_with_limit(path.as_ref(), MAX_JSON_DOCUMENT_READ_SIZE, label)?;
        Self::parse(content)
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
