// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Typed wrappers for format-detected encrypted content.
//!
//! These newtypes guarantee that format detection has already been performed
//! on the underlying string, eliminating redundant `detect_format` calls
//! across feature functions.

use crate::format::detection::{detect_format, InputFormat};
use crate::format::kv::document::parse_kv_document_with_source;
use crate::format::schema::document::parse_file_enc_str;
use crate::model::file_enc::FileEncDocument;
use crate::model::kv_enc::document::KvEncDocument;
use crate::{Error, Result};

/// File-enc content (JSON string, format-detected but unparsed).
#[derive(Debug, Clone)]
pub struct FileEncContent {
    content: String,
    source_name: String,
}

/// KV-enc content (text string, format-detected but unparsed).
#[derive(Debug, Clone)]
pub struct KvEncContent {
    content: String,
    source_name: String,
}

/// Format-detected encrypted content for dispatch.
pub enum EncContent {
    FileEnc(FileEncContent),
    KvEnc(KvEncContent),
}

impl FileEncContent {
    /// Construct after verifying the content is file-enc format.
    pub fn detect(content: String) -> Result<Self> {
        Self::detect_with_source(content, "file-enc content")
    }

    /// Construct after verifying the content is file-enc format.
    pub fn detect_with_source(content: String, source_name: impl Into<String>) -> Result<Self> {
        match detect_format(&content)? {
            InputFormat::FileEnc => Ok(Self::new_unchecked_with_source(content, source_name)),
            other => Err(Error::Parse {
                message: format!("Expected file-enc format, detected {:?}", other),
                source: None,
            }),
        }
    }

    /// Construct without format detection (caller guarantees file-enc format).
    pub fn new_unchecked(content: String) -> Self {
        Self::new_unchecked_with_source(content, "file-enc content")
    }

    /// Construct without format detection (caller guarantees file-enc format).
    pub fn new_unchecked_with_source(content: String, source_name: impl Into<String>) -> Self {
        Self {
            content,
            source_name: source_name.into(),
        }
    }

    /// Parse the JSON content into a `FileEncDocument`.
    pub fn parse(&self) -> Result<FileEncDocument> {
        parse_file_enc_str(&self.content, &self.source_name)
    }

    /// Serialize a `FileEncDocument` back to pretty-printed JSON.
    pub fn from_document(doc: &FileEncDocument) -> Result<Self> {
        let json = serde_json::to_string_pretty(doc).map_err(|e| Error::Parse {
            message: format!("Failed to serialize FileEncDocument: {}", e),
            source: Some(Box::new(e)),
        })?;
        Ok(Self::new_unchecked(json))
    }

    /// Access the underlying string.
    pub fn as_str(&self) -> &str {
        &self.content
    }
}

impl KvEncContent {
    /// Construct after verifying the content is kv-enc format.
    pub fn detect(content: String) -> Result<Self> {
        Self::detect_with_source(content, "kv-enc content")
    }

    /// Construct after verifying the content is kv-enc format.
    pub fn detect_with_source(content: String, source_name: impl Into<String>) -> Result<Self> {
        match detect_format(&content)? {
            InputFormat::KvEnc => Ok(Self::new_unchecked_with_source(content, source_name)),
            other => Err(Error::Parse {
                message: format!("Expected kv-enc format, detected {:?}", other),
                source: None,
            }),
        }
    }

    /// Construct without format detection (caller guarantees kv-enc format).
    pub fn new_unchecked(content: String) -> Self {
        Self::new_unchecked_with_source(content, "kv-enc content")
    }

    /// Construct without format detection (caller guarantees kv-enc format).
    pub fn new_unchecked_with_source(content: String, source_name: impl Into<String>) -> Self {
        Self {
            content,
            source_name: source_name.into(),
        }
    }

    /// Parse the content into a `KvEncDocument`.
    pub fn parse(&self) -> Result<KvEncDocument> {
        parse_kv_document_with_source(&self.content, &self.source_name)
    }

    /// Access the underlying string.
    pub fn as_str(&self) -> &str {
        &self.content
    }
}

impl EncContent {
    /// Detect format and wrap in the appropriate variant.
    pub fn detect(content: String) -> Result<Self> {
        Self::detect_with_source(content, "encrypted content")
    }

    /// Detect format and wrap in the appropriate variant.
    pub fn detect_with_source(content: String, source_name: impl Into<String>) -> Result<Self> {
        let source_name = source_name.into();
        match detect_format(&content)? {
            InputFormat::FileEnc => Ok(Self::FileEnc(FileEncContent::new_unchecked_with_source(
                content,
                source_name,
            ))),
            InputFormat::KvEnc => Ok(Self::KvEnc(KvEncContent::new_unchecked_with_source(
                content,
                source_name,
            ))),
            other => Err(Error::Parse {
                message: format!("Expected file-enc or kv-enc format, detected {:?}", other),
                source: None,
            }),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/format_content_internal_test.rs"]
mod tests;
