// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for canonical `kid` handling.

use crate::{Error, Result};

const KID_LENGTH: usize = 32;
const DISPLAY_GROUP_SIZE: usize = 4;
const HALF_DISPLAY_LENGTH: usize = 16;

/// Normalize user-provided `kid` input to canonical serialized form.
pub fn normalize_kid(input: &str) -> Result<String> {
    let canonical = normalize_kid_query(input)?;
    if canonical.len() != KID_LENGTH {
        return Err(Error::build_invalid_argument_error(format!(
            "kid must be {KID_LENGTH} Crockford Base32 characters after normalization"
        )));
    }
    Ok(canonical)
}

/// Normalize a CLI `kid` query.
///
/// Accepts canonical `kid`, dashed display form, and any non-empty prefix.
pub fn normalize_kid_query(input: &str) -> Result<String> {
    let normalized = input
        .bytes()
        .filter(|byte| *byte != b'-')
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<u8>>();

    if normalized.is_empty() || normalized.len() > KID_LENGTH {
        return Err(Error::build_invalid_argument_error(format!(
            "kid must be 1 to {KID_LENGTH} Crockford Base32 characters after normalization"
        )));
    }

    let query = String::from_utf8(normalized)
        .map_err(|_| Error::build_invalid_argument_error("kid must be valid ASCII"))?;

    if !query.bytes().all(is_crockford_base32_byte) {
        return Err(Error::build_invalid_argument_error(
            "kid must use Crockford Base32 characters only",
        ));
    }

    Ok(query)
}

/// Resolve a canonical `kid` from a candidate set using exact/display/prefix input.
pub fn resolve_unique_kid<I, S>(candidates: I, query: &str) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let normalized_query = normalize_kid_query(query)?;
    let matches = candidates
        .into_iter()
        .map(|candidate| normalize_kid(candidate.as_ref()))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|candidate| candidate.starts_with(&normalized_query))
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [resolved] => Ok(resolved.clone()),
        [] => Err(Error::NotFound {
            message: format!("kid '{}' not found", query),
        }),
        _ => {
            let displays = matches
                .iter()
                .map(|kid| format_kid_display(kid).unwrap_or_else(|_| kid.clone()))
                .collect::<Vec<_>>()
                .join(", ");
            Err(Error::InvalidArgument {
                message: format!("kid '{}' is ambiguous; matches: {}", query, displays),
            })
        }
    }
}

/// Build the human-friendly dashed display form of a canonical `kid`.
pub fn format_kid_display(canonical_kid: &str) -> Result<String> {
    let canonical = normalize_kid(canonical_kid)?;
    let mut output = String::with_capacity(KID_LENGTH + (KID_LENGTH / DISPLAY_GROUP_SIZE - 1));

    for (index, chunk) in canonical.as_bytes().chunks(DISPLAY_GROUP_SIZE).enumerate() {
        if index > 0 {
            output.push('-');
        }
        output.push_str(std::str::from_utf8(chunk).expect("canonical kid must stay ASCII"));
    }

    Ok(output)
}

/// Build the first half of the human-friendly dashed display form of a canonical `kid`.
pub fn format_kid_half_display(canonical_kid: &str) -> Result<String> {
    let canonical = normalize_kid(canonical_kid)?;
    let half = &canonical[..HALF_DISPLAY_LENGTH];
    let mut output =
        String::with_capacity(HALF_DISPLAY_LENGTH + (HALF_DISPLAY_LENGTH / DISPLAY_GROUP_SIZE - 1));

    for (index, chunk) in half.as_bytes().chunks(DISPLAY_GROUP_SIZE).enumerate() {
        if index > 0 {
            output.push('-');
        }
        output.push_str(std::str::from_utf8(chunk).expect("canonical kid must stay ASCII"));
    }

    Ok(output)
}

/// Build dashed display form for human-facing output.
///
/// This function is **lossy**: if `kid` is not a valid canonical `kid`, it returns the input as-is.
pub fn format_kid_display_lossy(kid: &str) -> String {
    format_kid_display(kid).unwrap_or_else(|_| kid.to_string())
}

/// Build dashed half-display form for human-facing output.
///
/// This function is **lossy**: if `kid` is not a valid canonical `kid`, it returns the input as-is.
pub fn format_kid_half_display_lossy(kid: &str) -> String {
    format_kid_half_display(kid).unwrap_or_else(|_| kid.to_string())
}

fn is_crockford_base32_byte(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z')
}
