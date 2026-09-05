// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc format parser implementation

use crate::format::kv::HEADER_LINE_PREFIX;
use crate::format::FormatError;
use crate::model::kv_enc::line::{KvEncLine, KvEncVersion};
use crate::{Error, Result};

/// Prefix, display tag, and constructor of a control line that carries one token.
type TokenControlLine = (&'static str, &'static str, fn(String) -> KvEncLine);

/// Control lines carrying a single token, with the line each one builds.
const TOKEN_CONTROL_LINES: [TokenControlLine; 3] = [
    (":HEAD ", "HEAD", |token| KvEncLine::Head { token }),
    (":WRAP ", "WRAP", |token| KvEncLine::Wrap { token }),
    (":SIG ", "SIG", |token| KvEncLine::Sig { token }),
];

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
        // Header line: ":KAPSARO_KV 1" (v1 only)
        if let Some(version_text) = line.strip_prefix(HEADER_LINE_PREFIX) {
            return Self::parse_header_line(version_text);
        }

        for (prefix, tag, build_line) in TOKEN_CONTROL_LINES {
            if let Some(token) = line.strip_prefix(prefix) {
                return Self::parse_token_control_line(tag, token, line, build_line);
            }
        }

        // Unknown control tag
        Err(
            FormatError::build_parse_error(format!("Unknown control tag in kv-enc line: {}", line))
                .into(),
        )
    }

    /// Parse the version of a header line: ":KAPSARO_KV 1" (v1 only).
    fn parse_header_line(version_text: &str) -> Result<KvEncLine> {
        let version = KvEncVersion::parse(version_text).ok_or_else(|| {
            Error::from(FormatError::build_parse_error(format!(
                "Unsupported kv-enc version: {} (only v1 is supported)",
                version_text
            )))
        })?;
        Ok(KvEncLine::Header { version })
    }

    /// Parse a control line whose payload is a single token: ":HEAD", ":WRAP", ":SIG".
    fn parse_token_control_line(
        tag: &str,
        token: &str,
        line: &str,
        build_line: fn(String) -> KvEncLine,
    ) -> Result<KvEncLine> {
        if token.is_empty() {
            return Err(FormatError::build_parse_error(format!(
                "kv-enc v1: {} line must have a token: {}",
                tag, line
            ))
            .into());
        }
        Ok(build_line(token.to_string()))
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
                "kv-enc v1: comment lines are not allowed: {}",
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
mod format_kv_enc_parser_internal_test;

#[cfg(test)]
#[path = "../../../../tests/unit/internal/format_kv_enc_parser_test.rs"]
mod format_kv_enc_parser_test;
