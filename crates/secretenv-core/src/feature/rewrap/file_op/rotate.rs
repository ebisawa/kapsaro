// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rotate content key for file-enc content.

use crate::crypto::rng::fill_secret_array;
use crate::crypto::types::data::Plaintext;
use crate::crypto::types::keys::MasterKey;
use crate::feature::decrypt::file::decrypt_file_payload;
use crate::feature::envelope::key_schedule::FileKeySchedule;
use crate::feature::envelope::payload::encrypt_file_payload_content;
use crate::feature::envelope::wrap::{build_wraps_for_recipients, WrapFormat};
use crate::feature::recipient::resolve_snapshot_verified_recipients;
use crate::model::file_enc::FileEncDocumentProtected;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::public_key::VerifiedRecipientKey;
use crate::Result;

/// Rotate content key for file-enc content.
pub(in crate::feature::rewrap) fn rotate_file_key(
    protected: &mut FileEncDocumentProtected,
    verified: &VerifiedFileEncDocument,
    old_content_key: &MasterKey,
    target_members: &[VerifiedRecipientKey],
    debug: bool,
) -> Result<MasterKey> {
    let old_schedule = FileKeySchedule::extract(old_content_key, &protected.sid)?;
    let old_payload_key = old_schedule.derive_content_key()?;
    let plaintext_bytes =
        decrypt_file_payload(verified, &old_payload_key, debug, "rotate_file_key")?;
    let plaintext_obj = Plaintext::from(plaintext_bytes.as_slice());
    let new_content_key_bytes = fill_secret_array::<32>()?;
    let new_content_key = MasterKey::from_zeroizing(new_content_key_bytes);
    let new_schedule = FileKeySchedule::extract(&new_content_key, &protected.sid)?;
    let new_xchacha_key = new_schedule.derive_content_key()?;
    protected.payload.encrypted = encrypt_file_payload_content(
        &plaintext_obj,
        &new_xchacha_key,
        &protected.payload.protected,
        debug,
        "rotate_file_key",
    )?;

    let current_recipients = protected.recipients();
    let attested_pubkeys =
        resolve_snapshot_verified_recipients(target_members, &current_recipients)?;
    protected.wrap = build_wraps_for_recipients(
        &attested_pubkeys,
        &protected.sid,
        &new_content_key,
        WrapFormat::File,
        debug,
    )?;
    Ok(new_content_key)
}
