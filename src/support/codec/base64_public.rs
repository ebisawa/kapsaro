// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public base64/base64url helpers.
//!
//! ```compile_fail
//! use secretenv::support::codec::base64_public::encode_base64url_nopad;
//! use secretenv::support::secret::SecretArray;
//!
//! let secret = SecretArray::new([0u8; 32]);
//! let _ = encode_base64url_nopad(&secret);
//! ```

use crate::crypto::types::data::Ciphertext;
use crate::support::limits::{MAX_BASE64_CIPHERTEXT_LENGTH, MAX_BASE64_TOKEN_LENGTH};
use crate::{Error, Result};

use super::{
    decode_base64url_input_len, decode_into, decode_standard_input_len, encode_public,
    Base64Variant, STANDARD_ALPHABET, URL_SAFE_ALPHABET,
};

pub fn encode_base64url_nopad(data: &[u8]) -> String {
    encode_public(data, URL_SAFE_ALPHABET, false)
}

pub fn encode_base64_standard(data: &[u8]) -> String {
    encode_public(data, STANDARD_ALPHABET, true)
}

pub fn encode_base64_standard_nopad(data: &[u8]) -> String {
    encode_public(data, STANDARD_ALPHABET, false)
}

pub fn decode_base64url_nopad(data: &str, field_name: &str) -> Result<Vec<u8>> {
    decode_base64url_nopad_with_limit(data, field_name, MAX_BASE64_CIPHERTEXT_LENGTH)
}

pub fn decode_base64url_nopad_array<const N: usize>(
    data: &str,
    field_name: &str,
) -> Result<[u8; N]> {
    let len = decode_base64url_input_len(data, field_name)?;
    if len != N {
        return Err(Error::Crypto {
            message: format!("Invalid {} length: expected {}, got {}", field_name, N, len),
            source: None,
        });
    }

    let mut out = [0u8; N];
    decode_into(
        data,
        data.len(),
        Base64Variant::UrlSafe,
        &mut out,
        field_name,
    )?;
    Ok(out)
}

pub fn decode_base64url_nopad_token(data: &str, field_name: &str) -> Result<Vec<u8>> {
    decode_base64url_nopad_with_limit(data, field_name, MAX_BASE64_TOKEN_LENGTH)
}

pub fn decode_base64url_nopad_ciphertext(data: &str, field_name: &str) -> Result<Ciphertext> {
    Ok(Ciphertext::from(decode_base64url_nopad(data, field_name)?))
}

pub fn decode_base64_standard(data: &str, field_name: &str) -> Result<Vec<u8>> {
    let layout = decode_standard_input_len(data, field_name)?;
    let mut out = vec![0u8; layout.output_len];
    decode_into(
        data,
        layout.payload_len,
        Base64Variant::Standard,
        &mut out,
        field_name,
    )?;
    Ok(out)
}

fn decode_base64url_nopad_with_limit(
    data: &str,
    field_name: &str,
    max_len: usize,
) -> Result<Vec<u8>> {
    if data.len() > max_len {
        return Err(Error::Parse {
            message: format!(
                "{} exceeds maximum base64url length ({} bytes > {} bytes)",
                field_name,
                data.len(),
                max_len
            ),
            source: None,
        });
    }

    let len = decode_base64url_input_len(data, field_name)?;
    let mut out = vec![0u8; len];
    decode_into(
        data,
        data.len(),
        Base64Variant::UrlSafe,
        &mut out,
        field_name,
    )?;
    Ok(out)
}
