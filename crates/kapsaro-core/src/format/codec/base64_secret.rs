// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Secret base64url helpers.
//!
//! ```compile_fail
//! use kapsaro_core::format::codec::base64_secret::encode_base64url_nopad_secret_32;
//!
//! let public = [0u8; 32];
//! let _ = encode_base64url_nopad_secret_32(&public);
//! ```

use crate::support::limits::MAX_BASE64_CIPHERTEXT_LENGTH;
use crate::support::secret::{SecretArray, SecretBytes, SecretString};
use crate::{Error, Result};
use zeroize::Zeroizing;

use super::{
    decode_base64url_input_len, decode_into, encode_secret, Base64Variant, URL_SAFE_ALPHABET,
};

pub fn encode_base64url_nopad_secret_bytes(data: &SecretBytes) -> SecretString {
    SecretString::try_from(encode_secret(data.as_bytes(), URL_SAFE_ALPHABET, false))
        .expect("base64 output must be valid UTF-8")
}

pub fn encode_base64url_nopad_secret_32(data: &SecretArray<32>) -> SecretString {
    encode_secret_array(data)
}

pub fn encode_base64url_nopad_secret_64(data: &SecretArray<64>) -> SecretString {
    encode_secret_array(data)
}

pub fn decode_base64url_nopad_secret_bytes(data: &str, field_name: &str) -> Result<SecretBytes> {
    if data.len() > MAX_BASE64_CIPHERTEXT_LENGTH {
        return Err(Error::build_parse_error(format!(
            "{} exceeds maximum base64url length ({} bytes > {} bytes)",
            field_name,
            data.len(),
            MAX_BASE64_CIPHERTEXT_LENGTH
        )));
    }

    let len = decode_base64url_input_len(data, field_name)?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    decode_into(
        data,
        data.len(),
        Base64Variant::UrlSafe,
        &mut out,
        field_name,
    )?;
    Ok(SecretBytes::from_zeroizing(out))
}

pub fn decode_base64url_nopad_secret_32(data: &str, field_name: &str) -> Result<SecretArray<32>> {
    decode_secret_array(data, field_name)
}

pub fn decode_base64url_nopad_secret_64(data: &str, field_name: &str) -> Result<SecretArray<64>> {
    decode_secret_array(data, field_name)
}

fn encode_secret_array<const N: usize>(data: &SecretArray<N>) -> SecretString {
    SecretString::try_from(encode_secret(data.as_array(), URL_SAFE_ALPHABET, false))
        .expect("base64 output must be valid UTF-8")
}

fn decode_secret_array<const N: usize>(data: &str, field_name: &str) -> Result<SecretArray<N>> {
    let len = decode_base64url_input_len(data, field_name)?;
    if len != N {
        return Err(Error::build_crypto_error(format!(
            "Invalid {} length: expected {}, got {}",
            field_name, N, len
        )));
    }

    let mut out = Zeroizing::new([0u8; N]);
    decode_into(
        data,
        data.len(),
        Base64Variant::UrlSafe,
        &mut out[..],
        field_name,
    )?;
    Ok(SecretArray::from_zeroizing(out))
}
