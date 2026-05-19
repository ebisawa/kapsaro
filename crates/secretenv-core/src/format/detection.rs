// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Format detection
//!
//! Automatic input type detection:
//! - kv-enc: Starts with ":SECRETENV_KV 7"
//! - file-enc: JSON with "format": "secretenv:format:file-enc@5"
//! - kv-plain: UTF-8 text, 2+ non-empty/non-comment lines, 60%+ KEY=VALUE format

use crate::format::kv::HEADER_LINE_V7;
use crate::model::wire::format;
use crate::support::json_limits::validate_json_limits;
use crate::Result;

/// Detected input format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFormat {
    /// kv-enc format (:SECRETENV_KV 7)
    KvEnc,

    /// file-enc format (JSON with secretenv:format:file-enc@5)
    FileEnc,

    /// kv-plain format (dotenv-style KEY=VALUE)
    KvPlain,

    /// Unknown/unsupported format
    Unknown,
}

/// Detect input format from content
pub fn detect_format(content: &str) -> Result<InputFormat> {
    // Empty content
    if content.trim().is_empty() {
        return Ok(InputFormat::Unknown);
    }

    // Check formats in order of specificity
    if let Some(format) = detect_kv_enc(content)? {
        return Ok(format);
    }

    if let Some(format) = detect_file_enc(content)? {
        return Ok(format);
    }

    if let Some(format) = detect_kv_plain(content)? {
        return Ok(format);
    }

    Ok(InputFormat::Unknown)
}

/// Detect kv-enc format from content
///
/// Format: ":SECRETENV_KV 7" (colon prefix + space separator)
fn detect_kv_enc(content: &str) -> Result<Option<InputFormat>> {
    if content.lines().next() == Some(HEADER_LINE_V7) {
        return Ok(Some(InputFormat::KvEnc));
    }
    Ok(None)
}

/// Detect file-enc format from content
///
/// Format: JSON with `protected.format = "secretenv:format:file-enc@5"`
fn detect_file_enc(content: &str) -> Result<Option<InputFormat>> {
    if !content.trim_start().starts_with('{') {
        return Ok(None);
    }

    validate_json_limits(content.as_bytes())?;
    let value = match serde_json::from_str::<serde_json::Value>(content) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    if let Some(protected) = value.get("protected") {
        if let Some(format) = protected.get("format").and_then(|v| v.as_str()) {
            if format == format::FILE_ENC_V5 {
                return Ok(Some(InputFormat::FileEnc));
            }
        }
    }

    Ok(None)
}

/// Detect kv-plain format from content
///
/// Format: UTF-8 text, 2+ non-empty/non-comment lines, 60%+ KEY=VALUE format
fn detect_kv_plain(content: &str) -> Result<Option<InputFormat>> {
    let lines: Vec<&str> = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .collect();

    // Require at least 2 non-empty/non-comment lines
    if lines.len() < 2 {
        return Ok(None);
    }

    // Count KEY=VALUE lines
    let kv_count = lines.iter().filter(|line| is_key_value_line(line)).count();
    let kv_percentage = (kv_count as f64 / lines.len() as f64) * 100.0;

    // 60% threshold
    if kv_percentage >= 60.0 {
        return Ok(Some(InputFormat::KvPlain));
    }

    Ok(None)
}

/// Check if a line matches KEY=VALUE format
fn is_key_value_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.split_once('=').is_some_and(|(key, _)| {
        !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}
