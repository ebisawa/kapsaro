// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc format parser implementation

use crate::format::kv::HEADER_LINE_PREFIX;
use crate::format::FormatError;
use crate::model::kv_enc::line::{KvEncLine, KvEncVersion};
use crate::{Error, Result};

/// KV-enc format parser
pub struct KvEncParser<'a> {
    content: &'a str,
}

impl<'a> KvEncParser<'a> {
    /// Create a new parser for the given content
    pub fn new(content: &'a str) -> Self {
        Self { content }
    }

    /// Parse a control line (starts with `:`).
    fn parse_control_line(line: &str) -> Result<KvEncLine> {
        // Header line: ":SECRETENV_KV 9" (v9 only)
        if let Some(version_str) = line.strip_prefix(HEADER_LINE_PREFIX) {
            let version_num: u32 = version_str.parse().map_err(|_| {
                FormatError::build_parse_error(format!(
                    "Invalid version in header: {}",
                    version_str
                ))
            })?;
            let version = KvEncVersion::from_u32(version_num)
                .ok_or_else(|| {
                    FormatError::build_parse_error(format!(
                        "Unsupported kv-enc version: {} (only v9 is supported)",
                        version_num
                    ))
                })
                .map_err(Error::from)?;
            return Ok(KvEncLine::Header { version });
        }

        // HEAD line: ":HEAD {token}"
        if let Some(token) = line.strip_prefix(":HEAD ") {
            if token.is_empty() {
                return Err(FormatError::build_parse_error(format!(
                    "kv-enc v9: HEAD line must have a token: {}",
                    line
                ))
                .into());
            }
            return Ok(KvEncLine::Head {
                token: token.to_string(),
            });
        }

        // WRAP line: ":WRAP {token}"
        if let Some(token) = line.strip_prefix(":WRAP ") {
            if token.is_empty() {
                return Err(FormatError::build_parse_error(format!(
                    "kv-enc v9: WRAP line must have a token: {}",
                    line
                ))
                .into());
            }
            return Ok(KvEncLine::Wrap {
                token: token.to_string(),
            });
        }

        // SIG line: ":SIG {token}"
        if let Some(token) = line.strip_prefix(":SIG ") {
            if token.is_empty() {
                return Err(FormatError::build_parse_error(format!(
                    "kv-enc v9: SIG line must have a token: {}",
                    line
                ))
                .into());
            }
            return Ok(KvEncLine::Sig {
                token: token.to_string(),
            });
        }

        // Unknown control tag
        Err(
            FormatError::build_parse_error(format!("Unknown control tag in kv-enc line: {}", line))
                .into(),
        )
    }

    /// Parse a single line
    pub fn parse_line(line: &str) -> Result<KvEncLine> {
        // Empty line
        if line.is_empty() {
            return Ok(KvEncLine::Empty);
        }

        // Comment lines are not allowed
        if line.starts_with('#') {
            return Err(FormatError::build_parse_error(format!(
                "kv-enc v9: comment lines are not allowed: {}",
                line
            ))
            .into());
        }

        // Control lines start with `:`
        if line.starts_with(':') {
            return Self::parse_control_line(line);
        }

        // KV line: "{key} {token}" (space separator)
        if let Some(space_pos) = line.find(' ') {
            let key = line[..space_pos].to_string();
            let token = line[space_pos + 1..].to_string();
            return Ok(KvEncLine::KV { key, token });
        }

        // Invalid line format
        Err(FormatError::build_parse_error(format!("Invalid kv-enc line format: {}", line)).into())
    }

    /// Parse all lines in the content
    pub fn parse_all(&self) -> Result<Vec<KvEncLine>> {
        // DoS protection: check file size limit
        if self.content.len() > crate::support::limits::MAX_KV_ENC_FILE_SIZE {
            return Err(Error::build_parse_error(format!(
                "kv-enc file exceeds maximum size limit ({} bytes > {} bytes)",
                self.content.len(),
                crate::support::limits::MAX_KV_ENC_FILE_SIZE
            )));
        }

        let mut lines = Vec::new();

        for line in self.content.lines() {
            lines.push(Self::parse_line(line)?);
        }

        // DoS protection: check KEY line count
        let key_count = lines
            .iter()
            .filter(|l| matches!(l, KvEncLine::KV { .. }))
            .count();
        if key_count > crate::support::limits::MAX_KV_KEY_LINES {
            return Err(Error::build_parse_error(format!(
                "kv-enc file exceeds maximum KEY line count ({} > {})",
                key_count,
                crate::support::limits::MAX_KV_KEY_LINES
            )));
        }

        Ok(lines)
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/format_kv_enc_parser_internal_test.rs"]
mod internal_tests;
