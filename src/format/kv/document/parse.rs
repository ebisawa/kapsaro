// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::format::kv::document::structure::{
    parse_kv_signature_token, validate_kv_file_structure, validate_kv_tokens,
};
use crate::format::kv::enc::canonical::extract_kv_header_tokens;
use crate::format::kv::enc::parser::KvEncParser;
use crate::format::schema::document::{
    parse_kv_head_token, parse_kv_signature_token as parse_kv_signature_token_json,
    parse_kv_wrap_token,
};
use crate::model::kv_enc::document::KvEncDocument;
use crate::Result;

pub(super) fn parse_kv_document(content: &str) -> Result<KvEncDocument> {
    let lines = KvEncParser::new(content).parse_all()?;
    validate_kv_file_structure(&lines)?;
    validate_kv_tokens(&lines)?;

    let (head_token, wrap_token) = extract_kv_header_tokens(&lines)?;
    let signature_token = parse_kv_signature_token(&lines)?;
    let head = parse_kv_head_token(&head_token)?;
    let wrap = parse_kv_wrap_token(&wrap_token)?;
    let _signature = parse_kv_signature_token_json(&signature_token)?;

    Ok(KvEncDocument::new(
        content.to_string(),
        lines,
        head,
        wrap,
        signature_token,
    ))
}
