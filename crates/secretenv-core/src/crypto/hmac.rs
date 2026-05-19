// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! HMAC primitives for authenticated tag computation.
//!
//! Provides generic HMAC-SHA256 helpers without artifact-specific policy.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::Result;

pub const HMAC_SHA256_TAG_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

pub fn compute_hmac_sha256_tag(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| crate::crypto::build_crypto_error("HMAC-SHA256", e))?;
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    debug_assert_eq!(tag.len(), HMAC_SHA256_TAG_LEN);
    Ok(tag.to_vec())
}

pub fn verify_hmac_sha256_tag(key: &[u8], message: &[u8], expected_tag: &[u8]) -> Result<bool> {
    let actual_tag = compute_hmac_sha256_tag(key, message)?;
    Ok(actual_tag.ct_eq(expected_tag).into())
}
