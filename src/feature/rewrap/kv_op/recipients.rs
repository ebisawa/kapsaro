// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient operations for kv-enc content.

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::wrap::build_wrap_item_for_kv;
use crate::feature::recipient::{build_new_wrap_items, resolve_verified_recipients};
use crate::format::kv::enc::canonical::extract_recipients_from_wrap;
use crate::model::kv_enc::header::KvWrap;
use crate::model::public_key::VerifiedRecipientKey;
use crate::Result;
use uuid::Uuid;

/// Add recipients to kv-enc wrap data.
///
/// Note: For kv-enc, each wrap item must include all recipients (existing + newly added)
/// at the time of creation. This is why we update `current_recipients` in the loop
/// and normalize recipients for each wrap item individually.
pub fn add_kv_recipients(
    sid: &Uuid,
    wrap_data: &mut KvWrap,
    new_recipients: &[String],
    master_key: &MasterKey,
    key_ctx: &CryptoContext,
    target_members: Option<&[VerifiedRecipientKey]>,
    debug: bool,
) -> Result<()> {
    let current_recipients = extract_recipients_from_wrap(wrap_data);
    let wrap_items = build_new_wrap_items(
        &current_recipients,
        wrap_data.wrap.len(),
        new_recipients,
        key_ctx,
        target_members,
        debug,
        |attested| build_wrap_item_for_kv(sid, attested, master_key, debug),
    )?;
    wrap_data.wrap.extend(wrap_items);

    Ok(())
}

pub fn rewrite_kv_recipient_wraps(
    sid: &Uuid,
    wrap_data: &mut KvWrap,
    refreshed_recipients: &[String],
    master_key: &MasterKey,
    key_ctx: &CryptoContext,
    target_members: Option<&[VerifiedRecipientKey]>,
    debug: bool,
) -> Result<()> {
    let refreshed_members =
        resolve_verified_recipients(target_members, key_ctx, refreshed_recipients, debug)?;
    wrap_data
        .wrap
        .retain(|wrap| !refreshed_recipients.contains(&wrap.rid));
    for member in &refreshed_members {
        wrap_data
            .wrap
            .push(build_wrap_item_for_kv(sid, member, master_key, debug)?);
    }
    Ok(())
}
