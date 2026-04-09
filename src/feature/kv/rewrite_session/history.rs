// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::disclosure::{add_to_removed_history, merge_removed_history};
use crate::format::schema::document::parse_kv_entry_token;
use crate::model::kv_enc::header::KvWrap;
use crate::model::kv_enc::line::KvEncLine;
use crate::Result;

pub(super) fn detect_disclosed_entries(lines: &[KvEncLine]) -> bool {
    lines.iter().any(|line| {
        if let KvEncLine::KV { token, .. } = line {
            parse_kv_entry_token(token.as_str())
                .map(|entry| entry.disclosed)
                .unwrap_or(false)
        } else {
            false
        }
    })
}

pub(super) fn merge_removed_history_from_old(
    new_wrap: &mut KvWrap,
    old_wrap: &KvWrap,
    removed_recipients: &[String],
) -> Result<()> {
    for rid in removed_recipients {
        if let Some(wrap_item) = old_wrap.wrap.iter().find(|wrap| wrap.rid == *rid) {
            add_to_removed_history(&mut new_wrap.removed_recipients, rid, &wrap_item.kid)?;
        }
    }
    merge_removed_history(
        &mut new_wrap.removed_recipients,
        old_wrap.removed_recipients.as_ref(),
    );
    Ok(())
}
