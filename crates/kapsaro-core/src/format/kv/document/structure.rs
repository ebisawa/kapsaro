// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Validates the line structure and tokens of a parsed kv-enc v1 file.
//! Enforces line order (HEADER, HEAD, WRAP, entries, SIG), unique keys, and well-formed tokens.

use crate::format::kv::dotenv::is_valid_key_name;
use crate::format::schema::document::{
    parse_kv_entry_token_with_source,
    parse_kv_signature_token_with_source as parse_kv_signature_document_with_source,
    parse_kv_wrap_token_with_source,
};
use crate::model::kv_enc::document::{KvEncEntry, KvFileSignature};
use crate::model::kv_enc::line::KvEncLine;
use crate::{Error, Result};

use super::parse::token_source;

pub(super) struct ValidatedKvTokens {
    pub entries: Vec<KvEncEntry>,
    pub signature_token: String,
    pub signature: KvFileSignature,
}

pub(super) fn validate_kv_tokens(
    lines: &[KvEncLine],
    source_name: &str,
) -> Result<ValidatedKvTokens> {
    let mut entries = Vec::new();
    let mut signature = None;

    for line in lines {
        match line {
            KvEncLine::Wrap { token } => validate_wrap_token(token, source_name)?,
            KvEncLine::KV { key, token } => {
                entries.push(validate_entry_token(key, token, source_name)?);
            }
            KvEncLine::Sig { token } => {
                signature = Some(ValidatedSignature {
                    token: token.clone(),
                    signature: validate_signature_token(token, source_name)?,
                });
            }
            _ => {}
        }
    }

    let signature = signature.ok_or_else(missing_sig_error)?;
    Ok(ValidatedKvTokens {
        entries,
        signature_token: signature.token,
        signature: signature.signature,
    })
}

pub(super) fn validate_kv_file_structure(lines: &[KvEncLine]) -> Result<()> {
    let logical_lines: Vec<(usize, &KvEncLine)> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| !matches!(line, KvEncLine::Empty))
        .collect();

    if logical_lines.is_empty() {
        return Err(Error::build_parse_error(
            "kv-enc file is empty or contains only empty lines and comments".to_string(),
        ));
    }

    validate_kv_header_lines(&logical_lines)?;
    validate_no_data_after_sig(lines)?;
    validate_kv_keys(lines)
}

fn missing_sig_error() -> Error {
    Error::build_crypto_error("kv-enc v1 has no SIG line (v9 requires signatures)".to_string())
}

fn validate_wrap_token(token: &str, source_name: &str) -> Result<()> {
    parse_kv_wrap_token_with_source(token, &token_source(source_name, "WRAP token"))?;
    Ok(())
}

fn validate_entry_token(key: &str, token: &str, source_name: &str) -> Result<KvEncEntry> {
    let entry =
        parse_kv_entry_token_with_source(token, &token_source(source_name, "KV entry token"))
            .map_err(|e| {
                Error::build_parse_error(format!(
                    "Invalid KV entry token structure for key '{}': {}",
                    key, e
                ))
            })?;

    Ok(KvEncEntry::new(key.to_string(), token.to_string(), entry))
}

fn validate_signature_token(token: &str, source_name: &str) -> Result<KvFileSignature> {
    parse_kv_signature_document_with_source(token, &token_source(source_name, "SIG token"))
}

struct ValidatedSignature {
    token: String,
    signature: KvFileSignature,
}

/// One line a kv-enc document must carry exactly once, at a known position.
struct RequiredLine {
    matcher: fn(&KvEncLine) -> bool,
    label: &'static str,
    missing_rule: &'static str,
    position_rule: &'static str,
    position_message: &'static str,
}

fn validate_required_line(
    logical_lines: &[(usize, &KvEncLine)],
    required: &RequiredLine,
    expected_position: usize,
) -> Result<()> {
    validate_required_line_count(logical_lines, required)?;
    if logical_lines.len() <= expected_position
        || !(required.matcher)(logical_lines[expected_position].1)
    {
        return Err(Error::build_verification_error(
            required.position_rule.to_string(),
            required.position_message.to_string(),
        ));
    }
    Ok(())
}

fn validate_required_line_count(
    logical_lines: &[(usize, &KvEncLine)],
    required: &RequiredLine,
) -> Result<()> {
    let count = logical_lines
        .iter()
        .filter(|(_, line)| (required.matcher)(line))
        .count();
    if count == 0 {
        return Err(Error::build_verification_error(
            required.missing_rule.to_string(),
            format!("kv-enc v1: missing {} line", required.label),
        ));
    }
    if count > 1 {
        return Err(Error::build_verification_error(
            "E_SCHEMA_INVALID".to_string(),
            format!(
                "kv-enc v1: {} line appears {} times (must be exactly once)",
                required.label, count
            ),
        ));
    }
    Ok(())
}

fn validate_no_data_after_sig(lines: &[KvEncLine]) -> Result<()> {
    let mut found_sig = false;
    for line in lines {
        match line {
            KvEncLine::Sig { .. } => found_sig = true,
            KvEncLine::KV { .. }
            | KvEncLine::Head { .. }
            | KvEncLine::Wrap { .. }
            | KvEncLine::Header { .. } => {
                if found_sig {
                    return Err(Error::build_verification_error(
                        "E_SCHEMA_INVALID".to_string(),
                        "kv-enc v1: data lines (HEAD/WRAP/KV) must not appear after :SIG line"
                            .to_string(),
                    ));
                }
            }
            KvEncLine::Empty => {}
        }
    }
    Ok(())
}

fn validate_kv_keys(lines: &[KvEncLine]) -> Result<()> {
    let mut seen_keys = std::collections::HashSet::new();
    for line in lines {
        if let KvEncLine::KV { key, .. } = line {
            if !is_valid_key_name(key) {
                return Err(Error::build_verification_error(
                    "E_SCHEMA_INVALID".to_string(),
                    format!(
                        "kv-enc v1: invalid KEY format '{}' (must match ^[A-Za-z_][A-Za-z0-9_]*$)",
                        key
                    ),
                ));
            }
            if !seen_keys.insert(key.clone()) {
                return Err(Error::build_verification_error(
                    "E_DUPLICATE_KEY".to_string(),
                    format!(
                        "kv-enc v1: duplicate KEY '{}' (each KEY must appear only once)",
                        key
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_kv_header_lines(logical_lines: &[(usize, &KvEncLine)]) -> Result<()> {
    for (position, required) in leading_required_lines().iter().enumerate() {
        validate_required_line(logical_lines, required, position)?;
    }
    // The signature closes the document, so its position follows the entries.
    validate_required_line(logical_lines, &required_sig_line(), logical_lines.len() - 1)
}

/// The lines that open a kv-enc document, in the order they must appear.
fn leading_required_lines() -> [RequiredLine; 3] {
    [
        RequiredLine {
            matcher: |line| matches!(line, KvEncLine::Header { .. }),
            label: ":KAPSARO_KV",
            missing_rule: "E_SCHEMA_INVALID",
            position_rule: "E_SCHEMA_INVALID",
            position_message: "kv-enc v1: :KAPSARO_KV 1 must be the first line",
        },
        RequiredLine {
            matcher: |line| matches!(line, KvEncLine::Head { .. }),
            label: ":HEAD",
            missing_rule: "E_SCHEMA_INVALID",
            position_rule: "E_SCHEMA_INVALID",
            position_message: "kv-enc v1: :HEAD must be the second line (after :KAPSARO_KV 1)",
        },
        RequiredLine {
            matcher: |line| matches!(line, KvEncLine::Wrap { .. }),
            label: ":WRAP",
            missing_rule: "E_WRAP_LINE_MISSING",
            position_rule: "E_WRAP_LINE_POSITION",
            position_message: "kv-enc v1: :WRAP must be the third line (after :HEAD)",
        },
    ]
}

fn required_sig_line() -> RequiredLine {
    RequiredLine {
        matcher: |line| matches!(line, KvEncLine::Sig { .. }),
        label: ":SIG",
        missing_rule: "E_SIG_LINE_MISSING",
        position_rule: "E_SCHEMA_INVALID",
        position_message: "kv-enc v1: :SIG must be the last logical line (after all KV entries)",
    }
}
