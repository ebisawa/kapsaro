// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient operations for file-enc content (add, remove).

use crate::feature::context::crypto::CryptoContext;
use crate::feature::disclosure::add_to_removed_history;
use crate::feature::envelope::unwrap::unwrap_master_key_for_file_with_context;
use crate::feature::envelope::wrap::build_wrap_item_for_file;
use crate::feature::recipient::{
    build_new_wrap_items, check_recipient_exists, print_recipient_not_found_warning,
    resolve_verified_recipients, validate_not_empty_recipients,
};
use crate::model::file_enc::FileEncDocumentProtected;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::Result;

/// Remove recipients from file-enc content.
///
/// Note: For file-enc, recipients can be removed by directly filtering the wrap items.
/// Each recipient is processed individually to update the removal history.
pub fn remove_file_recipients(
    protected: &mut FileEncDocumentProtected,
    recipients_to_remove: &[String],
) -> Result<()> {
    let current_recipients = protected.recipients();

    // Collect wrap items to remove (with their kids) before removing them
    let mut to_remove: Vec<(String, String)> = Vec::new();
    for recipient_handle in recipients_to_remove {
        if !check_recipient_exists(&current_recipients, recipient_handle) {
            print_recipient_not_found_warning(recipient_handle);
            continue;
        }

        // Find the wrap item to get its kid
        if let Some(wrap_item) = protected
            .wrap
            .iter()
            .find(|w| w.recipient_handle == *recipient_handle)
        {
            to_remove.push((recipient_handle.clone(), wrap_item.kid.clone()));
        }
    }

    // Record removals in history
    for (recipient_handle, kid) in &to_remove {
        add_to_removed_history(&mut protected.removed_recipients, recipient_handle, kid)?;
    }

    // Remove wrap items
    for (recipient_handle, _kid) in &to_remove {
        protected
            .wrap
            .retain(|w| w.recipient_handle != *recipient_handle);
    }

    // Validate that at least one recipient remains
    let remaining_recipients: Vec<String> = protected
        .wrap
        .iter()
        .map(|w| w.recipient_handle.clone())
        .collect();
    validate_not_empty_recipients(&remaining_recipients)?;

    Ok(())
}

/// Add recipients to file-enc content.
///
/// Note: For file-enc, all wrap items use the same recipients list (existing recipients
/// at the time of addition). This is why we normalize recipients once before the loop.
pub fn add_file_recipients(
    protected: &mut FileEncDocumentProtected,
    verified: &VerifiedFileEncDocument,
    new_recipients: &[String],
    key_ctx: &CryptoContext,
    target_members: Option<&[crate::model::public_key::VerifiedRecipientKey]>,
    debug: bool,
) -> Result<()> {
    let content_key =
        unwrap_master_key_for_file_with_context(verified, &key_ctx.member_handle, key_ctx, debug)?
            .value;
    let current_recipients = protected.recipients();
    let wrap_items = build_new_wrap_items(
        &current_recipients,
        protected.wrap.len(),
        new_recipients,
        key_ctx,
        target_members,
        debug,
        |attested| build_wrap_item_for_file(attested, &protected.sid, &content_key, debug),
    )?;
    protected.wrap.extend(wrap_items);

    Ok(())
}

pub fn rewrite_file_recipient_wraps(
    protected: &mut FileEncDocumentProtected,
    verified: &VerifiedFileEncDocument,
    recipients_to_refresh: &[String],
    key_ctx: &CryptoContext,
    target_members: Option<&[crate::model::public_key::VerifiedRecipientKey]>,
    debug: bool,
) -> Result<()> {
    let content_key =
        unwrap_master_key_for_file_with_context(verified, &key_ctx.member_handle, key_ctx, debug)?
            .value;
    let refreshed_members =
        resolve_verified_recipients(target_members, key_ctx, recipients_to_refresh, debug)?;

    protected
        .wrap
        .retain(|wrap| !recipients_to_refresh.contains(&wrap.recipient_handle));
    for member in &refreshed_members {
        protected.wrap.push(build_wrap_item_for_file(
            member,
            &protected.sid,
            &content_key,
            debug,
        )?);
    }

    Ok(())
}
