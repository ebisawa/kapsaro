// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests the wire-level checks one stored wrap entry is held to.
//! Fixes that the key id is read as the canonical form a document carries.

use super::validate_wrap_items;
use crate::model::common::WrapItem;
use crate::model::wire::algorithm;

const CONTEXT: &str = "Document";
const RECIPIENT: &str = "alice@example.com";
/// A stored key id, and the same one spelled the way it is shown to an
/// operator. A stored document never carries the second form.
const RECIPIENT_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
const RECIPIENT_KID_DISPLAY_FORM: &str = "7m2q-9d4r-1h8v-w6pk-t3xn-c5jy-2f9a-r8gd";
/// 32 encapsulated-key bytes and 48 ciphertext bytes, base64url without padding.
const ENC_32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const CT_48: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn wrap_item(kid: &str) -> WrapItem {
    WrapItem {
        recipient_handle: RECIPIENT.to_string(),
        kid: kid.to_string(),
        alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
        enc: ENC_32.to_string(),
        ct: CT_48.to_string(),
    }
}

#[test]
fn test_canonical_wrap_kid_is_accepted() {
    validate_wrap_items(&[wrap_item(RECIPIENT_KID)], CONTEXT)
        .expect("a stored wrap entry carries a canonical kid");
}

/// The key id names the recipient key the entry is bound to and is covered by
/// the signature, so a display form is refused rather than normalized into a
/// name the stored bytes never carried.
#[test]
fn test_display_form_wrap_kid_is_rejected() {
    let error = validate_wrap_items(&[wrap_item(RECIPIENT_KID_DISPLAY_FORM)], CONTEXT)
        .expect_err("a stored wrap entry must carry a canonical kid");

    assert!(
        error.format_user_message().contains("canonical"),
        "got: {}",
        error.format_user_message()
    );
}
