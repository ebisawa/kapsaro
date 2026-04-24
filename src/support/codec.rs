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

pub(crate) fn encode_public(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = vec![0u8; compute_encoded_len(data.len(), pad)];
    fill_encoded(data, &mut out, alphabet, pad);
    String::from_utf8(out).expect("base64 output must be valid ASCII")
}

pub(crate) fn encode_secret(data: &[u8], alphabet: &[u8; 64], pad: bool) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; compute_encoded_len(data.len(), pad)]);
    fill_encoded(data, &mut out, alphabet, pad);
    out
}

pub(crate) fn compute_encoded_len(input_len: usize, pad: bool) -> usize {
    let chunks = input_len / 3;
    let rem = input_len % 3;
    let base = chunks * 4;
    match (rem, pad) {
        (0, _) => base,
        (_, true) => base + 4,
        (1, false) => base + 2,
        (2, false) => base + 3,
        _ => base,
    }
}

fn fill_encoded(data: &[u8], out: &mut [u8], alphabet: &[u8; 64], pad: bool) {
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
        1 => encode_tail_one(data[in_idx], &mut out[out_idx..], alphabet, pad),
        2 => encode_tail_two(
            &data[in_idx..in_idx + 2],
            &mut out[out_idx..],
            alphabet,
            pad,
        ),
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

fn encode_tail_one(input: u8, out: &mut [u8], alphabet: &[u8; 64], pad: bool) {
    out[0] = alphabet[(input >> 2) as usize];
    out[1] = alphabet[((input & 0x03) << 4) as usize];
    if pad {
        out[2] = b'=';
        out[3] = b'=';
    }
}

fn encode_tail_two(input: &[u8], out: &mut [u8], alphabet: &[u8; 64], pad: bool) {
    let b0 = input[0];
    let b1 = input[1];
    out[0] = alphabet[(b0 >> 2) as usize];
    out[1] = alphabet[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
    out[2] = alphabet[((b1 & 0x0f) << 2) as usize];
    if pad {
        out[3] = b'=';
    }
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

fn validate_standard_chars(data: &str, field_name: &str) -> Result<usize> {
    let mut padding_started = false;
    let mut padding_count = 0usize;
    let mut payload_len = data.len();

    for (idx, byte) in data.bytes().enumerate() {
        if byte == b'=' {
            if !padding_started {
                payload_len = idx;
                padding_started = true;
            }
            padding_count += 1;
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

    if padding_count > 2 {
        return Err(invalid_length_error(
            field_name,
            "Invalid base64 padding length (maximum 2 '=' characters)",
        ));
    }
    if padding_count > 0 && !data.len().is_multiple_of(4) {
        return Err(invalid_length_error(
            field_name,
            "Padded base64 length must be a multiple of 4",
        ));
    }
    if padding_count == 1 && payload_len % 4 != 3 {
        return Err(invalid_length_error(
            field_name,
            "Invalid base64 padding placement",
        ));
    }
    if padding_count == 2 && payload_len % 4 != 2 {
        return Err(invalid_length_error(
            field_name,
            "Invalid base64 padding placement",
        ));
    }

    Ok(payload_len)
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
            out[0] = (a << 2) | (b >> 4);
            Ok(())
        }
        3 => {
            let a = decode_symbol_checked(chunk[0], variant, field_name)?;
            let b = decode_symbol_checked(chunk[1], variant, field_name)?;
            let c = decode_symbol_checked(chunk[2], variant, field_name)?;
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
    Error::Parse {
        message: format!("{} {}", field_name, detail),
        source: None,
    }
}

fn invalid_length_error(field_name: &str, detail: &str) -> Error {
    Error::Parse {
        message: format!("{}: {}", field_name, detail),
        source: None,
    }
}
