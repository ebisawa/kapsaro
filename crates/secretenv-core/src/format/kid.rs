// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Canonical `kid` derivation helpers.

use crate::format::jcs::normalize_to_bytes;
use crate::Result;
use serde_json::Value;
use sha2::{Digest, Sha256};

const CROCKFORD_BASE32_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Derive a deterministic `kid` from `PublicKey@7.protected_without_kid`.
pub fn derive_public_key_kid(protected_without_kid: &Value) -> Result<String> {
    let canonical_bytes = normalize_to_bytes(protected_without_kid)?;
    let digest = Sha256::digest(&canonical_bytes);
    Ok(encode_crockford_base32(&digest[..20]))
}

fn encode_crockford_base32(bytes: &[u8]) -> String {
    debug_assert_eq!((bytes.len() * 8) % 5, 0);

    let total_groups = bytes.len() * 8 / 5;
    let mut output = String::with_capacity(total_groups);

    for group_index in 0..total_groups {
        let mut value = 0u8;
        let bit_start = group_index * 5;

        for bit_offset in 0..5 {
            let bit_index = bit_start + bit_offset;
            let byte = bytes[bit_index / 8];
            let bit = (byte >> (7 - (bit_index % 8))) & 1;
            value = (value << 1) | bit;
        }

        output.push(CROCKFORD_BASE32_ALPHABET[value as usize] as char);
    }

    output
}
