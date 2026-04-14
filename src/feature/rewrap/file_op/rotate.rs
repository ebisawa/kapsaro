// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rotate content key for file-enc content.

use crate::crypto::rng::fill_secret_array;
use crate::crypto::types::data::Plaintext;
use crate::crypto::types::keys::{MasterKey, XChaChaKey};
use crate::feature::context::crypto::CryptoContext;
use crate::feature::decrypt::file::decrypt_file_payload;
use crate::feature::envelope::payload::encrypt_file_payload_content;
use crate::feature::envelope::unwrap::unwrap_master_key_for_file_with_context;
use crate::feature::envelope::wrap::{build_wraps_for_recipients, WrapFormat};
use crate::feature::recipient::resolve_verified_recipients;
use crate::model::file_enc::FileEncDocumentProtected;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::public_key::VerifiedRecipientKey;
use crate::Result;

/// Rotate content key for file-enc content.
pub fn rotate_file_key(
    protected: &mut FileEncDocumentProtected,
    verified: &VerifiedFileEncDocument,
    key_ctx: &CryptoContext,
    target_members: Option<&[VerifiedRecipientKey]>,
    debug: bool,
) -> Result<()> {
    let old_content_key =
        unwrap_master_key_for_file_with_context(verified, &key_ctx.member_id, key_ctx, debug)?
            .value;
    let plaintext_bytes =
        decrypt_file_payload(verified, &old_content_key, debug, "rotate_file_key")?;
    let plaintext_obj = Plaintext::from(plaintext_bytes.as_slice());
    let new_content_key_bytes = fill_secret_array::<32>()?;
    let new_content_key = MasterKey::from_zeroizing(new_content_key_bytes);
    let new_xchacha_key = XChaChaKey::from_slice(new_content_key.as_bytes())?;
    protected.payload.encrypted = encrypt_file_payload_content(
        &plaintext_obj,
        &new_xchacha_key,
        &protected.payload.protected,
        debug,
        "rotate_file_key",
    )?;

    let current_recipients = protected.recipients();
    let attested_pubkeys =
        resolve_verified_recipients(target_members, key_ctx, &current_recipients, debug)?;
    protected.wrap = build_wraps_for_recipients(
        &attested_pubkeys,
        &protected.sid,
        &new_content_key,
        WrapFormat::File,
        debug,
    )?;
    Ok(())
}
