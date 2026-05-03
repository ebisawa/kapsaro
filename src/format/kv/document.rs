// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc document parsing and validation.

mod parse;
mod structure;

use crate::model::kv_enc::document::KvEncDocument;
use crate::model::kv_enc::line::KvEncLine;
use crate::Result;

pub fn parse_kv_document(content: &str) -> Result<KvEncDocument> {
    parse::parse_kv_document(content, "kv-enc content")
}

pub fn parse_kv_document_with_source(content: &str, source_name: &str) -> Result<KvEncDocument> {
    parse::parse_kv_document(content, source_name)
}

pub fn validate_kv_file_structure(lines: &[KvEncLine]) -> Result<()> {
    structure::validate_kv_file_structure(lines)
}
