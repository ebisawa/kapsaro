// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Base64url encoding/decoding utilities
//!
//! Provides shared utilities for base64url (URL-safe, no padding) encoding/decoding

use crate::crypto::types::data::Ciphertext;
use crate::support::limits::{MAX_BASE64_CIPHERTEXT_LENGTH, MAX_BASE64_TOKEN_LENGTH};
use crate::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use zeroize::Zeroizing;

// ============================================================================
// Base64url Helpers
// ============================================================================

/// Encode bytes to base64url (no padding)
pub fn b64_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url to bytes with a descriptive error
///
/// This function enforces strict base64url decoding:
/// - Rejects input exceeding `MAX_BASE64_CIPHERTEXT_LENGTH` (universal backstop)
/// - Rejects padding (`=`)
/// - Rejects whitespace and control characters
/// - Only accepts base64url character set (A-Za-z0-9_-)
pub fn b64_decode(data: &str, field_name: &str) -> Result<Vec<u8>> {
    if data.len() > MAX_BASE64_CIPHERTEXT_LENGTH {
        return Err(Error::Parse {
            message: format!(
                "{} exceeds maximum base64url length ({} bytes > {} bytes)",
                field_name,
                data.len(),
                MAX_BASE64_CIPHERTEXT_LENGTH
            ),
            source: None,
        });
    }
    // Check for invalid characters (whitespace, padding, etc.)
    if data.contains('=') {
        return Err(Error::Parse {
            message: format!(
                "{} contains padding ('='), which is not allowed in base64url",
                field_name
            ),
            source: None,
        });
    }
    if data.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::Parse {
            message: format!(
                "{} contains whitespace or control characters, which are not allowed",
                field_name
            ),
            source: None,
        });
    }
    // Check for invalid base64url characters (only A-Za-z0-9_- allowed)
    if !data
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(Error::Parse {
            message: format!(
                "{} contains invalid characters (only A-Za-z0-9_- allowed in base64url)",
                field_name
            ),
            source: None,
        });
    }
    URL_SAFE_NO_PAD.decode(data).map_err(|e| Error::Parse {
        message: format!("Invalid {}: {}", field_name, e),
        source: Some(Box::new(e)),
    })
}

/// Decode base64url and convert to fixed-size array
///
/// This function uses Zeroizing to ensure that the intermediate Vec<u8>
/// is zeroed when dropped, preventing secret data from remaining in memory.
pub fn b64_decode_array<const N: usize>(data: &str, field_name: &str) -> Result<[u8; N]> {
    // Wrap the intermediate Vec<u8> in Zeroizing to ensure it's zeroed on drop
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(b64_decode(data, field_name)?);
    bytes.as_slice().try_into().map_err(|_| Error::Crypto {
        message: format!(
            "Invalid {} length: expected {}, got {}",
            field_name,
            N,
            bytes.len()
        ),
        source: None,
    })
}

/// Decode base64url and convert to a fixed-size secret array without an extra plain copy.
pub fn b64_decode_secret_array<const N: usize>(
    data: &str,
    field_name: &str,
) -> Result<Zeroizing<[u8; N]>> {
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(b64_decode(data, field_name)?);
    if bytes.len() != N {
        return Err(Error::Crypto {
            message: format!(
                "Invalid {} length: expected {}, got {}",
                field_name,
                N,
                bytes.len()
            ),
            source: None,
        });
    }

    let mut out = Zeroizing::new([0u8; N]);
    out.as_mut().copy_from_slice(bytes.as_slice());
    Ok(out)
}

/// Decode base64url token with stricter size limit (`MAX_BASE64_TOKEN_LENGTH`)
///
/// Use this for protocol tokens (HEAD, WRAP, SIG, KV entry tokens).
/// Enforces a 1 MiB limit instead of the 16 MiB universal backstop.
pub fn b64_decode_token(data: &str, field_name: &str) -> Result<Vec<u8>> {
    if data.len() > MAX_BASE64_TOKEN_LENGTH {
        return Err(Error::Parse {
            message: format!(
                "{} exceeds maximum token length ({} bytes > {} bytes)",
                field_name,
                data.len(),
                MAX_BASE64_TOKEN_LENGTH
            ),
            source: None,
        });
    }
    b64_decode(data, field_name)
}

/// Decode base64url ciphertext to Ciphertext type
///
/// This is a convenience function that decodes base64url-encoded ciphertext
/// and returns it as a type-safe Ciphertext wrapper.
///
/// Note: Ciphertext is not secret data, so we don't need Zeroizing here.
/// However, if this is used for secret data in the future, consider
/// using Zeroizing<Vec<u8>> internally.
pub fn b64_decode_ciphertext(data: &str, field_name: &str) -> Result<Ciphertext> {
    let bytes = b64_decode(data, field_name)?;
    Ok(Ciphertext::from(bytes))
}
