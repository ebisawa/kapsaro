// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient operations for file-enc content (add, remove).

use crate::crypto::types::keys::MasterKey;
use crate::feature::disclosure::add_to_removed_history;
use crate::feature::envelope::wrap::build_wrap_item_for_file;
use crate::feature::recipient::{
    build_new_wrap_items, check_recipient_exists, replace_recipient_wrap_items,
    validate_not_empty_recipients,
};
use crate::model::file_enc::FileEncDocumentProtected;
use crate::model::public_key::VerifiedRecipientKey;
use crate::Result;
use tracing::warn;

/// Remove recipients from file-enc content.
///
/// Note: For file-enc, recipients can be removed by directly filtering the wrap items.
/// Each recipient is processed individually to update the removal history.
pub(in crate::feature::rewrap) fn remove_file_recipients(
    protected: &mut FileEncDocumentProtected,
    recipients_to_remove: &[String],
) -> Result<()> {
    let current_recipients = protected.recipients();

    // Collect wrap items to remove (with their kids) before removing them
    let mut to_remove: Vec<(String, String)> = Vec::new();
    for recipient_handle in recipients_to_remove {
        if !check_recipient_exists(&current_recipients, recipient_handle) {
            warn!(
                "[CRYPTO] Warning: {} is not a recipient, skipping",
                recipient_handle
            );
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
pub(in crate::feature::rewrap) fn add_file_recipients(
    protected: &mut FileEncDocumentProtected,
    content_key: &MasterKey,
    new_recipients: &[String],
    target_members: &[VerifiedRecipientKey],
    debug: bool,
) -> Result<()> {
    let current_recipients = protected.recipients();
    let wrap_items = build_new_wrap_items(
        &current_recipients,
        protected.wrap.len(),
        new_recipients,
        target_members,
        |attested| build_wrap_item_for_file(attested, &protected.sid, content_key, debug),
    )?;
    protected.wrap.extend(wrap_items);

    Ok(())
}

pub(in crate::feature::rewrap) fn rewrite_file_recipient_wraps(
    protected: &mut FileEncDocumentProtected,
    content_key: &MasterKey,
    recipients_to_refresh: &[String],
    target_members: &[VerifiedRecipientKey],
    debug: bool,
) -> Result<()> {
    replace_recipient_wrap_items(
        &mut protected.wrap,
        recipients_to_refresh,
        target_members,
        |member| build_wrap_item_for_file(member, &protected.sid, content_key, debug),
    )
}
