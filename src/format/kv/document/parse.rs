// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::format::kv::document::structure::{
    parse_kv_signature_token, validate_kv_file_structure, validate_kv_tokens,
};
use crate::format::kv::enc::canonical::extract_kv_header_tokens;
use crate::format::kv::enc::parser::KvEncParser;
use crate::format::schema::document::{
    parse_kv_head_token_with_source,
    parse_kv_signature_token_with_source as parse_kv_signature_token_json_with_source,
    parse_kv_wrap_token_with_source,
};
use crate::model::kv_enc::document::KvEncDocument;
use crate::Result;

pub(super) fn parse_kv_document(content: &str, source_name: &str) -> Result<KvEncDocument> {
    let lines = KvEncParser::new(content).parse_all()?;
    validate_kv_file_structure(&lines)?;
    validate_kv_tokens(&lines, source_name)?;

    let (head_token, wrap_token) = extract_kv_header_tokens(&lines)?;
    let signature_token = parse_kv_signature_token(&lines)?;
    let head =
        parse_kv_head_token_with_source(&head_token, &token_source(source_name, "HEAD token"))?;
    let wrap =
        parse_kv_wrap_token_with_source(&wrap_token, &token_source(source_name, "WRAP token"))?;
    let _signature = parse_kv_signature_token_json_with_source(
        &signature_token,
        &token_source(source_name, "SIG token"),
    )?;

    Ok(KvEncDocument::new(
        content.to_string(),
        lines,
        head,
        wrap,
        signature_token,
    ))
}

pub(super) fn token_source(source_name: &str, token_name: &str) -> String {
    if source_name == token_name {
        token_name.to_string()
    } else {
        format!("{} ({})", source_name, token_name)
    }
}
