// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests the write decision that every trust store mutation goes through.
//! Covers content changes, a rotated signer, and an already current signature.

use super::{judge_trust_store_write, TrustStoreWrite};

const CURRENT_SIGNER_KID: &str = "D4VE0000D4VE0000D4VE0000D4VE0000";
const STORED_SIGNER_KID: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";

#[test]
fn test_changed_content_is_saved_whatever_the_stored_signer_is() {
    assert_eq!(
        judge_trust_store_write(true, Some(STORED_SIGNER_KID), CURRENT_SIGNER_KID),
        TrustStoreWrite::Save
    );
    assert_eq!(
        judge_trust_store_write(true, Some(CURRENT_SIGNER_KID), CURRENT_SIGNER_KID),
        TrustStoreWrite::Save
    );
    assert_eq!(
        judge_trust_store_write(true, None, CURRENT_SIGNER_KID),
        TrustStoreWrite::Save
    );
}

#[test]
fn test_unchanged_content_signed_by_another_key_is_resigned() {
    assert_eq!(
        judge_trust_store_write(false, Some(STORED_SIGNER_KID), CURRENT_SIGNER_KID),
        TrustStoreWrite::Resign
    );
}

#[test]
fn test_unchanged_content_signed_by_the_current_key_is_skipped() {
    assert_eq!(
        judge_trust_store_write(false, Some(CURRENT_SIGNER_KID), CURRENT_SIGNER_KID),
        TrustStoreWrite::Skip
    );
    assert_eq!(
        judge_trust_store_write(false, None, CURRENT_SIGNER_KID),
        TrustStoreWrite::Skip
    );
}
