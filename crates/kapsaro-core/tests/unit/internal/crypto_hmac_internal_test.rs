// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests HMAC primitive helpers against known vectors.
//! Ensures callers receive raw primitive results and boolean verification.

use super::hmac::{compute_hmac_sha256_tag, verify_hmac_sha256_tag, HMAC_SHA256_TAG_LEN};

#[test]
fn compute_hmac_sha256_tag_matches_rfc4231_vector() {
    let key = [0x0b; 20];
    let tag = compute_hmac_sha256_tag(&key, b"Hi There").unwrap();

    assert_eq!(tag.len(), HMAC_SHA256_TAG_LEN);
    assert_eq!(
        hex::encode(tag),
        concat!(
            "b0344c61d8db38535ca8afceaf0bf12b",
            "881dc200c9833da726e9376c2e32cff7"
        )
    );
}

#[test]
fn verify_hmac_sha256_tag_returns_false_for_mismatch() {
    let key = b"key";
    let message = b"message";
    let tag = compute_hmac_sha256_tag(key, message).unwrap();

    assert!(verify_hmac_sha256_tag(key, message, &tag).unwrap());
    assert!(!verify_hmac_sha256_tag(b"other-key", message, &tag).unwrap());
}
