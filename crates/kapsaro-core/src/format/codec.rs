// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Internal base64/base64url codec implementations.

pub mod base64_public;
pub mod base64_secret;

use crate::{Error, Result};
use zeroize::Zeroizing;

pub(crate) const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub(crate) const URL_SAFE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Clone, Copy)]
pub(crate) enum Base64Variant {
    Standard,
    UrlSafe,
}

pub(crate) struct StandardDecodeLayout {
    pub(crate) payload_len: usize,
    pub(crate) output_len: usize,
}

/// Encode without padding, which is the only form kapsaro emits.
///
/// The padded form appears only on the way in, where OpenSSH spells its blobs,
/// and the decoders accept it there.
pub(crate) fn encode_public(data: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = vec![0u8; compute_encoded_len(data.len())];
    fill_encoded(data, &mut out, alphabet);
    String::from_utf8(out).expect("base64 output must be valid ASCII")
}

pub(crate) fn encode_secret(data: &[u8], alphabet: &[u8; 64]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; compute_encoded_len(data.len())]);
    fill_encoded(data, &mut out, alphabet);
    out
}

fn compute_encoded_len(input_len: usize) -> usize {
    let base = (input_len / 3) * 4;
    match input_len % 3 {
        0 => base,
        1 => base + 2,
        _ => base + 3,
    }
}

fn fill_encoded(data: &[u8], out: &mut [u8], alphabet: &[u8; 64]) {
    let mut in_idx = 0;
    let mut out_idx = 0;

    while in_idx + 3 <= data.len() {
        encode_full_block(
            &data[in_idx..in_idx + 3],
            &mut out[out_idx..out_idx + 4],
            alphabet,
        );
        in_idx += 3;
        out_idx += 4;
    }

    match data.len() - in_idx {
        1 => encode_tail_one(data[in_idx], &mut out[out_idx..], alphabet),
        2 => encode_tail_two(&data[in_idx..in_idx + 2], &mut out[out_idx..], alphabet),
        _ => {}
    }
}

fn encode_full_block(input: &[u8], out: &mut [u8], alphabet: &[u8; 64]) {
    let b0 = input[0];
    let b1 = input[1];
    let b2 = input[2];
    out[0] = alphabet[(b0 >> 2) as usize];
    out[1] = alphabet[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
    out[2] = alphabet[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize];
    out[3] = alphabet[(b2 & 0x3f) as usize];
}

fn encode_tail_one(input: u8, out: &mut [u8], alphabet: &[u8; 64]) {
    out[0] = alphabet[(input >> 2) as usize];
    out[1] = alphabet[((input & 0x03) << 4) as usize];
}

fn encode_tail_two(input: &[u8], out: &mut [u8], alphabet: &[u8; 64]) {
    let b0 = input[0];
    let b1 = input[1];
    out[0] = alphabet[(b0 >> 2) as usize];
    out[1] = alphabet[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
    out[2] = alphabet[((b1 & 0x0f) << 2) as usize];
}

pub(crate) fn decode_base64url_input_len(data: &str, field_name: &str) -> Result<usize> {
    validate_common_input(data, field_name)?;
    validate_base64url_chars(data, field_name)?;

    let rem = data.len() % 4;
    if rem == 1 {
        return Err(invalid_length_error(
            field_name,
            "Invalid base64url length (mod 4 must not be 1)",
        ));
    }

    Ok((data.len() / 4) * 3 + tail_output_len(rem))
}

pub(crate) fn decode_standard_input_len(
    data: &str,
    field_name: &str,
) -> Result<StandardDecodeLayout> {
    validate_common_input(data, field_name)?;
    let payload_len = validate_standard_chars(data, field_name)?;
    let rem = payload_len % 4;
    if rem == 1 {
        return Err(invalid_length_error(
            field_name,
            "Invalid base64 length (payload mod 4 must not be 1)",
        ));
    }

    Ok(StandardDecodeLayout {
        payload_len,
        output_len: (payload_len / 4) * 3 + tail_output_len(rem),
    })
}

fn tail_output_len(rem: usize) -> usize {
    match rem {
        0 => 0,
        2 => 1,
        3 => 2,
        _ => 0,
    }
}

fn validate_common_input(data: &str, field_name: &str) -> Result<()> {
    if data.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid_character_error(
            field_name,
            "contains whitespace or control characters",
        ));
    }
    Ok(())
}

fn validate_base64url_chars(data: &str, field_name: &str) -> Result<()> {
    if data.contains('=') {
        return Err(invalid_character_error(
            field_name,
            "contains padding ('='), which is not allowed in base64url",
        ));
    }
    if data
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Ok(());
    }
    Err(invalid_character_error(
        field_name,
        "contains invalid characters (only A-Za-z0-9_- allowed in base64url)",
    ))
}

/// Where the padding of a standard base64 string starts and how long it runs.
struct Base64Padding {
    /// Byte length of the encoded payload ahead of the first '='.
    payload_len: usize,
    /// Number of trailing '=' characters.
    count: usize,
}

fn validate_standard_chars(data: &str, field_name: &str) -> Result<usize> {
    let padding = validate_standard_char_set(data, field_name)?;
    enforce_padding_shape(&padding, data.len(), field_name)?;
    Ok(padding.payload_len)
}

/// Walk the string, rejecting symbols the alphabet does not hold.
///
/// Padding is only padding at the end, so a symbol appearing after the first
/// '=' is refused rather than counted as payload.
fn validate_standard_char_set(data: &str, field_name: &str) -> Result<Base64Padding> {
    let mut padding = Base64Padding {
        payload_len: data.len(),
        count: 0,
    };
    let mut padding_started = false;

    for (idx, byte) in data.bytes().enumerate() {
        if byte == b'=' {
            if !padding_started {
                padding.payload_len = idx;
                padding_started = true;
            }
            padding.count += 1;
            continue;
        }

        if padding_started {
            return Err(invalid_character_error(
                field_name,
                "contains non-padding characters after '='",
            ));
        }

        if decode_symbol(byte, Base64Variant::Standard).is_none() {
            return Err(invalid_character_error(
                field_name,
                "contains invalid characters for standard base64",
            ));
        }
    }

    Ok(padding)
}

/// Require the padding to be the one the payload length implies.
///
/// Base64 pads to a multiple of four, so a payload of a given remainder admits
/// exactly one padding length. Any other combination encodes a length that the
/// decoder would have to guess at.
fn enforce_padding_shape(padding: &Base64Padding, data_len: usize, field_name: &str) -> Result<()> {
    if padding.count > 2 {
        return Err(invalid_length_error(
            field_name,
            "Invalid base64 padding length (maximum 2 '=' characters)",
        ));
    }
    if padding.count > 0 && !data_len.is_multiple_of(4) {
        return Err(invalid_length_error(
            field_name,
            "Padded base64 length must be a multiple of 4",
        ));
    }
    let expected_remainder = match padding.count {
        1 => 3,
        2 => 2,
        _ => return Ok(()),
    };
    if padding.payload_len % 4 != expected_remainder {
        return Err(invalid_length_error(
            field_name,
            "Invalid base64 padding placement",
        ));
    }
    Ok(())
}

pub(crate) fn decode_into(
    data: &str,
    payload_len: usize,
    variant: Base64Variant,
    out: &mut [u8],
    field_name: &str,
) -> Result<()> {
    let payload = &data.as_bytes()[..payload_len];
    let full_len = payload_len - (payload_len % 4);
    let mut out_idx = 0usize;

    for chunk in payload[..full_len].chunks_exact(4) {
        decode_full_block(chunk, variant, &mut out[out_idx..out_idx + 3], field_name)?;
        out_idx += 3;
    }

    decode_tail(
        &payload[full_len..],
        variant,
        &mut out[out_idx..],
        field_name,
    )
}

fn decode_full_block(
    chunk: &[u8],
    variant: Base64Variant,
    out: &mut [u8],
    field_name: &str,
) -> Result<()> {
    let a = decode_symbol_checked(chunk[0], variant, field_name)?;
    let b = decode_symbol_checked(chunk[1], variant, field_name)?;
    let c = decode_symbol_checked(chunk[2], variant, field_name)?;
    let d = decode_symbol_checked(chunk[3], variant, field_name)?;
    out[0] = (a << 2) | (b >> 4);
    out[1] = ((b & 0x0f) << 4) | (c >> 2);
    out[2] = ((c & 0x03) << 6) | d;
    Ok(())
}

fn decode_tail(
    chunk: &[u8],
    variant: Base64Variant,
    out: &mut [u8],
    field_name: &str,
) -> Result<()> {
    match chunk.len() {
        0 => Ok(()),
        2 => {
            let a = decode_symbol_checked(chunk[0], variant, field_name)?;
            let b = decode_symbol_checked(chunk[1], variant, field_name)?;
            validate_unused_tail_bits(b, 0x0f, field_name)?;
            out[0] = (a << 2) | (b >> 4);
            Ok(())
        }
        3 => {
            let a = decode_symbol_checked(chunk[0], variant, field_name)?;
            let b = decode_symbol_checked(chunk[1], variant, field_name)?;
            let c = decode_symbol_checked(chunk[2], variant, field_name)?;
            validate_unused_tail_bits(c, 0x03, field_name)?;
            out[0] = (a << 2) | (b >> 4);
            out[1] = ((b & 0x0f) << 4) | (c >> 2);
            Ok(())
        }
        _ => Err(invalid_length_error(
            field_name,
            "Invalid trailing base64 length",
        )),
    }
}

fn validate_unused_tail_bits(value: u8, mask: u8, field_name: &str) -> Result<()> {
    if value & mask == 0 {
        return Ok(());
    }
    Err(invalid_character_error(
        field_name,
        "contains non-zero unused base64 tail bits",
    ))
}

fn decode_symbol_checked(byte: u8, variant: Base64Variant, field_name: &str) -> Result<u8> {
    decode_symbol(byte, variant).ok_or_else(|| {
        invalid_character_error(
            field_name,
            "contains characters outside the expected base64 alphabet",
        )
    })
}

fn decode_symbol(byte: u8, variant: Base64Variant) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' if matches!(variant, Base64Variant::Standard) => Some(62),
        b'/' if matches!(variant, Base64Variant::Standard) => Some(63),
        b'-' if matches!(variant, Base64Variant::UrlSafe) => Some(62),
        b'_' if matches!(variant, Base64Variant::UrlSafe) => Some(63),
        _ => None,
    }
}

fn invalid_character_error(field_name: &str, detail: &str) -> Error {
    Error::build_parse_error(format!("{} {}", field_name, detail))
}

fn invalid_length_error(field_name: &str, detail: &str) -> Error {
    Error::build_parse_error(format!("{}: {}", field_name, detail))
}

// Fixture encoder shared by the internal tests that build OpenSSH blobs. It
// lives in the test tree and compiles out of production builds.
#[cfg(test)]
#[path = "../../tests/unit/internal/format_codec_base64_fixtures.rs"]
pub(crate) mod format_codec_base64_fixtures;

#[cfg(test)]
#[path = "../../tests/unit/internal/format_codec_test.rs"]
mod format_codec_test;
