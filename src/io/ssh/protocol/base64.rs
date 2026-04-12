// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Base64 processing utilities for SSH formats

use crate::io::ssh::SshError;
use crate::support::codec::base64_public::decode_base64_standard;
use crate::Result;
use zeroize::Zeroizing;

/// Decode base64 content from armored format (skips BEGIN/END markers)
///
/// Extracts base64 content from armored format by:
/// 1. Filtering out lines starting with "-----"
/// 2. Joining remaining lines
/// 3. Decoding base64
pub fn decode_base64_armored(armored: &str) -> Result<Zeroizing<Vec<u8>>> {
    // Extract base64 content (skip BEGIN/END markers)
    let lines: Vec<&str> = armored
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();

    if lines.is_empty() {
        return Err(SshError::operation_failed("No base64 content in armored format").into());
    }

    // Join lines (ssh-keygen wraps base64 at 70 chars)
    let b64 = Zeroizing::new(lines.join(""));

    // Decode base64
    decode_base64_standard(b64.as_str(), "armored base64")
        .map(Zeroizing::new)
        .map_err(|e| {
            SshError::operation_failed_with_source(format!("Base64 decode failed: {}", e), e).into()
        })
}
