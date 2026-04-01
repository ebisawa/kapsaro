// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Transform kv-enc content: decrypt and re-encrypt with new recipients.

use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::signature::build_signing_context;
use crate::feature::kv::query::decrypt_all_kv_values;
use crate::feature::kv::rewrite_session::encrypt_and_sign_kv_map;
use crate::feature::rewrap::common::{add_to_removed_history, merge_removed_history};
use crate::feature::verify::recipients::load_and_verify_recipient_public_keys;
use crate::format::content::KvEncContent;
use crate::format::kv::detect_token_codec_from_kv_content;
use crate::format::kv::enc::canonical::parse_kv_wrap;
use crate::format::token::TokenCodec;
use crate::Result;
use std::collections::HashMap;

/// Decrypt kv-enc content to plaintext map.
pub(super) fn decrypt_kv_content(
    content: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<HashMap<String, String>> {
    let kv_content = KvEncContent::new_unchecked(content.to_string());
    decrypt_all_kv_values(&kv_content, &key_ctx.member_id, key_ctx, debug)
}

/// Encrypt plaintext map with new recipients.
pub(super) fn encrypt_kv_with_recipients(
    decrypted_content: &std::collections::HashMap<String, String>,
    new_recipients: &[String],
    key_ctx: &CryptoContext,
    token_codec: TokenCodec,
    disclosed: bool,
    debug: bool,
) -> Result<String> {
    let verified_members = load_and_verify_recipient_public_keys(
        key_ctx.pub_key_source.as_ref(),
        new_recipients,
        debug,
    )?;
    let signing = build_signing_context(key_ctx, debug)?;
    encrypt_and_sign_kv_map(
        decrypted_content,
        &verified_members,
        &signing,
        token_codec,
        disclosed,
        |_| Ok(()),
    )
}

/// Decrypt and re-encrypt kv-enc content with new recipients.
///
/// This is a common pattern used by replace_kv_recipients and remove_kv_recipients.
/// It handles the full cycle: parse → decrypt → encrypt with builder → sign.
/// Removed history is merged into the new WRAP before signing, avoiding double signing.
///
/// # Arguments
/// * `content` - Original kv-enc content
/// * `new_recipients` - New list of recipient member IDs
/// * `removed_recipients` - Recipients to add to removed history
/// * `key_ctx` - Member key context
/// * `disclosed` - Whether to mark entries as disclosed (true when removing recipients)
/// * `debug` - Enable debug logging
///
/// # Returns
/// Re-encrypted kv-enc content with updated recipients and removed history
pub fn decrypt_and_reencrypt_kv(
    content: &str,
    new_recipients: &[String],
    removed_recipients: &[String],
    key_ctx: &CryptoContext,
    disclosed: bool,
    debug: bool,
) -> Result<String> {
    let (_, _head_data, old_wrap) = parse_kv_wrap(content)?;
    let decrypted_content = decrypt_kv_content(content, key_ctx, debug)?;
    let token_codec = detect_token_codec_from_kv_content(content);

    let verified_members = load_and_verify_recipient_public_keys(
        key_ctx.pub_key_source.as_ref(),
        new_recipients,
        debug,
    )?;
    let signing = build_signing_context(key_ctx, debug)?;
    encrypt_and_sign_kv_map(
        &decrypted_content,
        &verified_members,
        &signing,
        token_codec,
        disclosed,
        |new_wrap| merge_removed_history_from_old(new_wrap, &old_wrap, removed_recipients),
    )
}

/// Merge removed history from old wrap into new wrap, adding newly removed recipients.
fn merge_removed_history_from_old(
    new_wrap: &mut crate::model::kv_enc::header::KvWrap,
    old_wrap: &crate::model::kv_enc::header::KvWrap,
    removed_recipients: &[String],
) -> Result<()> {
    for rid in removed_recipients {
        if let Some(wrap_item) = old_wrap.wrap.iter().find(|w| w.rid == *rid) {
            add_to_removed_history(&mut new_wrap.removed_recipients, rid, &wrap_item.kid)?;
        }
    }
    merge_removed_history(
        &mut new_wrap.removed_recipients,
        old_wrap.removed_recipients.as_ref(),
    );
    Ok(())
}
