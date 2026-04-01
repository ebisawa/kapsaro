// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient operations for kv-enc content (add, remove).

use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::wrap::build_wrap_item_for_kv;
use crate::feature::rewrap::common::{
    check_recipient_exists, resolve_attested_recipients, validate_not_empty_recipients,
    warn_recipient_not_found,
};
use crate::format::kv::enc::canonical::{extract_recipients_from_wrap, parse_kv_wrap};
use crate::model::kv_enc::header::KvWrap;
use crate::Result;
use uuid::Uuid;

use super::reencrypt::decrypt_and_reencrypt_kv;
use crate::feature::envelope::unwrap::unwrap_master_key_for_kv;
use crate::support::limits::validate_wrap_count;

/// Remove recipients from kv-enc content.
///
/// Note: For kv-enc, removing recipients requires full re-encryption of the content
/// because the master key must be re-wrapped for the remaining recipients.
pub fn remove_kv_recipients(
    content: &str,
    recipients_to_remove: &[String],
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<String> {
    let (_, _head_data, wrap_data) = parse_kv_wrap(content)?;
    let mut current_recipients = extract_recipients_from_wrap(&wrap_data);

    // Warn about recipients that don't exist
    for rid in recipients_to_remove {
        if !check_recipient_exists(&current_recipients, rid) {
            warn_recipient_not_found(rid);
        }
    }

    // Remove recipients from the list
    current_recipients.retain(|r| !recipients_to_remove.contains(r));

    // Validate that at least one recipient remains
    validate_not_empty_recipients(&current_recipients)?;

    // Re-encrypt the entire content with the updated recipients list
    // disclosed: true because removing recipients means secrets are potentially compromised
    decrypt_and_reencrypt_kv(
        content,
        &current_recipients,
        recipients_to_remove,
        key_ctx,
        true,
        debug,
    )
}

/// Add recipients to kv-enc wrap data.
///
/// Note: For kv-enc, each wrap item must include all recipients (existing + newly added)
/// at the time of creation. This is why we update `current_recipients` in the loop
/// and normalize recipients for each wrap item individually.
pub fn add_kv_recipients(
    sid: &Uuid,
    wrap_data: &mut KvWrap,
    new_recipients: &[String],
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<()> {
    let current_recipients = extract_recipients_from_wrap(wrap_data);
    let master_key = unwrap_master_key_for_kv(
        sid,
        &wrap_data.wrap,
        &key_ctx.member_id,
        &key_ctx.kid,
        &key_ctx.private_key,
        debug,
    )?;
    let attested_pubkeys =
        resolve_attested_recipients(key_ctx, new_recipients, &current_recipients, debug)?;
    validate_wrap_count(
        wrap_data.wrap.len() + attested_pubkeys.len(),
        "Updated wrap set",
    )?;

    for attested in &attested_pubkeys {
        let wrap_item = build_wrap_item_for_kv(sid, attested, &master_key, debug)?;
        wrap_data.wrap.push(wrap_item);
    }

    Ok(())
}
