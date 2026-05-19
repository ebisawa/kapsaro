// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! kv-enc canonical format and wrap parsing
//!
//! Provides functions to:
//! - Build canonical byte representation for signature verification
//! - Parse and extract HEAD and WRAP data from kv-enc content

use super::parser::KvEncParser;
use crate::format::kv::HEADER_LINE_PREFIX;
use crate::format::schema::document::{parse_kv_head_token, parse_kv_wrap_token};
use crate::format::FormatError;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::kv_enc::line::KvEncLine;
use crate::Result;

/// Build canonical bytes from kv-enc lines for signature verification
///
/// **Note**: This function assumes that the input lines have already been validated
/// by `validate_kv_file_structure()` to ensure correct structure (order, counts, etc.).
///
/// The canonical format includes:
/// - Header line: ":SECRETENV_KV {version}\n"
/// - HEAD line: ":HEAD {token}\n"
/// - WRAP line: ":WRAP {token}\n"
/// - KV lines: "{key} {token}\n"
///
/// Excludes:
/// - SIG lines (signature itself)
/// - Empty lines
///
/// # Arguments
/// * `lines` - Parsed kv-enc lines (must be validated beforehand)
///
/// # Returns
/// Canonical bytes for signature verification
pub fn build_canonical_bytes(lines: &[KvEncLine]) -> Vec<u8> {
    let mut canonical_bytes = Vec::new();
    for line in lines {
        match line {
            KvEncLine::Header { version } => {
                canonical_bytes
                    .extend_from_slice(format!("{}{}\n", HEADER_LINE_PREFIX, version).as_bytes());
            }
            KvEncLine::Head { token } => {
                canonical_bytes.extend_from_slice(format!(":HEAD {}\n", token).as_bytes());
            }
            KvEncLine::Wrap { token } => {
                canonical_bytes.extend_from_slice(format!(":WRAP {}\n", token).as_bytes());
            }
            KvEncLine::KV { key, token } => {
                canonical_bytes.extend_from_slice(format!("{} {}\n", key, token).as_bytes());
            }
            KvEncLine::Sig { .. } | KvEncLine::Empty => {
                // Skip SIG and empty lines (not part of signature)
            }
        }
    }
    canonical_bytes
}

/// Extract raw HEAD and WRAP token strings from parsed kv-enc lines.
///
/// # Arguments
/// * `lines` - Parsed kv-enc lines
///
/// # Returns
/// Tuple of (head_token, wrap_token) as raw strings
pub fn extract_kv_header_tokens(lines: &[KvEncLine]) -> Result<(String, String)> {
    let head_token = lines
        .iter()
        .find_map(|line| match line {
            KvEncLine::Head { token } => Some(token.clone()),
            _ => None,
        })
        .ok_or_else(|| FormatError::build_parse_error("HEAD line not found in kv-enc v7"))?;

    let wrap_token = lines
        .iter()
        .find_map(|line| match line {
            KvEncLine::Wrap { token } => Some(token.clone()),
            _ => None,
        })
        .ok_or_else(|| FormatError::build_parse_error("WRAP line not found in kv-enc v7"))?;

    Ok((head_token, wrap_token))
}

/// Parse kv-enc content and extract the HEAD and WRAP data
///
/// # Arguments
/// * `content` - kv-enc format content string
///
/// # Returns
/// Tuple of (parsed lines, HEAD data, WRAP data)
pub fn parse_kv_wrap(content: &str) -> Result<(Vec<KvEncLine>, KvHeader, KvWrap)> {
    let parser = KvEncParser::new(content);
    let lines = parser.parse_all()?;

    let (head_token, wrap_token) = extract_kv_header_tokens(&lines)?;

    // Decode tokens
    let head_data = parse_kv_head_token(&head_token)?;
    let wrap_data = parse_kv_wrap_token(&wrap_token)?;

    Ok((lines, head_data, wrap_data))
}

/// Extract recipient list from KvWrap
///
/// # Arguments
/// * `wrap` - KvWrap structure
///
/// # Returns
/// Vector of recipient member handles
pub fn extract_recipients_from_wrap(wrap: &KvWrap) -> Vec<String> {
    wrap.wrap
        .iter()
        .map(|w| w.recipient_handle.clone())
        .collect()
}
