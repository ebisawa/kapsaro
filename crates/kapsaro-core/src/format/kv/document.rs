// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc document parsing, validation, and unsigned draft assembly.
//! Owns line/token format state before feature code applies domain operations.

mod builder;
mod draft;
mod parse;
mod structure;

use crate::model::kv_enc::document::KvEncDocument;
use crate::model::kv_enc::line::KvEncLine;
use crate::Result;

pub use builder::KvDocumentBuilder;
pub(crate) use draft::{KvDocumentDraft, KvDocumentEntry, WrapSource};

pub fn parse_kv_document(content: &str) -> Result<KvEncDocument> {
    parse::parse_kv_document(content, "kv-enc content")
}

pub fn parse_kv_document_with_source(content: &str, source_name: &str) -> Result<KvEncDocument> {
    parse::parse_kv_document(content, source_name)
}

pub fn validate_kv_file_structure(lines: &[KvEncLine]) -> Result<()> {
    structure::validate_kv_file_structure(lines)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/format_kv_enc_ops_test.rs"]
mod format_kv_enc_ops_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/format_kv_enc_structure_test.rs"]
mod format_kv_enc_structure_test;
