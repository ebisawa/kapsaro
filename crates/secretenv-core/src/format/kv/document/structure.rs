// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

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
    Error::build_crypto_error("kv-enc v6 has no SIG line (v6 requires signatures)".to_string())
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

fn validate_unique_line(
    logical_lines: &[(usize, &KvEncLine)],
    matcher: fn(&KvEncLine) -> bool,
    label: &str,
    missing_rule: &str,
    expected_position: Option<usize>,
    position_rule: &str,
    position_message: &str,
) -> Result<()> {
    let count = logical_lines
        .iter()
        .filter(|(_, line)| matcher(line))
        .count();
    if count == 0 {
        return Err(Error::build_verification_error(
            missing_rule.to_string(),
            format!("kv-enc v6: missing {} line", label),
        ));
    }
    if count > 1 {
        return Err(Error::build_verification_error(
            "E_SCHEMA_INVALID".to_string(),
            format!(
                "kv-enc v6: {} line appears {} times (must be exactly once)",
                label, count
            ),
        ));
    }
    if let Some(pos) = expected_position {
        if logical_lines.len() <= pos || !matcher(logical_lines[pos].1) {
            return Err(Error::build_verification_error(
                position_rule.to_string(),
                position_message.to_string(),
            ));
        }
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
                        "kv-enc v6: data lines (HEAD/WRAP/KV) must not appear after :SIG line"
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
                        "kv-enc v6: invalid KEY format '{}' (must match ^[A-Za-z_][A-Za-z0-9_]*$)",
                        key
                    ),
                ));
            }
            if !seen_keys.insert(key.clone()) {
                return Err(Error::build_verification_error(
                    "E_DUPLICATE_KEY".to_string(),
                    format!(
                        "kv-enc v6: duplicate KEY '{}' (each KEY must appear only once)",
                        key
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_kv_header_lines(logical_lines: &[(usize, &KvEncLine)]) -> Result<()> {
    validate_unique_line(
        logical_lines,
        |line| matches!(line, KvEncLine::Header { .. }),
        ":SECRETENV_KV",
        "E_SCHEMA_INVALID",
        Some(0),
        "E_SCHEMA_INVALID",
        "kv-enc v6: :SECRETENV_KV 6 must be the first line",
    )?;
    validate_unique_line(
        logical_lines,
        |line| matches!(line, KvEncLine::Head { .. }),
        ":HEAD",
        "E_SCHEMA_INVALID",
        Some(1),
        "E_SCHEMA_INVALID",
        "kv-enc v6: :HEAD must be the second line (after :SECRETENV_KV 6)",
    )?;
    validate_unique_line(
        logical_lines,
        |line| matches!(line, KvEncLine::Wrap { .. }),
        ":WRAP",
        "E_WRAP_LINE_MISSING",
        Some(2),
        "E_WRAP_LINE_POSITION",
        "kv-enc v6: :WRAP must be the third line (after :HEAD)",
    )?;
    validate_unique_line(
        logical_lines,
        |line| matches!(line, KvEncLine::Sig { .. }),
        ":SIG",
        "E_SIG_LINE_MISSING",
        Some(logical_lines.len() - 1),
        "E_SCHEMA_INVALID",
        "kv-enc v6: :SIG must be the last logical line (after all KV entries)",
    )?;
    Ok(())
}
