// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::disclosure::{add_to_removed_history, merge_removed_history};
use crate::model::kv_enc::document::KvEncDocument;
use crate::model::kv_enc::header::KvWrap;
use crate::Result;

pub(super) fn detect_disclosed_entries(doc: &KvEncDocument) -> bool {
    doc.entries().iter().any(|entry| entry.value().disclosed)
}

pub(super) fn merge_removed_history_from_old(
    new_wrap: &mut KvWrap,
    old_wrap: &KvWrap,
    removed_recipients: &[String],
) -> Result<()> {
    for recipient_handle in removed_recipients {
        if let Some(wrap_item) = old_wrap
            .wrap
            .iter()
            .find(|wrap| wrap.recipient_handle == *recipient_handle)
        {
            add_to_removed_history(
                &mut new_wrap.removed_recipients,
                recipient_handle,
                &wrap_item.kid,
            )?;
        }
    }
    merge_removed_history(
        &mut new_wrap.removed_recipients,
        old_wrap.removed_recipients.as_ref(),
    );
    Ok(())
}
