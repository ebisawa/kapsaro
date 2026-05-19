// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verified content-key loading for file-enc rewrap operations.
//!
//! Keeps file rewrap paths aligned with normal decrypt validation boundaries.

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::key_possession::verify_file_key_possession;
use crate::feature::envelope::unwrap::unwrap_master_key_for_file_with_context;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::Result;

pub fn unwrap_verified_file_content_key(
    verified: &VerifiedFileEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<MasterKey> {
    let content_key =
        unwrap_master_key_for_file_with_context(verified, member_handle, key_ctx, debug)?.value;
    verify_file_key_possession(verified, content_key).map(|proof| proof.into_content_key())
}
