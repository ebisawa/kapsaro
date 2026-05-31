// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Disclosure history helpers shared across encrypted document features.

use crate::model::common::RemovedRecipient;
use crate::support::time::generate_current_timestamp;
use crate::Result;

/// Add a recipient to the removed recipient history list.
pub fn add_to_removed_history(
    removed_recipients: &mut Option<Vec<RemovedRecipient>>,
    recipient_handle: &str,
    kid: &str,
) -> Result<()> {
    let timestamp = generate_current_timestamp()?;
    let removed = RemovedRecipient {
        recipient_handle: recipient_handle.to_string(),
        kid: kid.to_string(),
        removed_at: timestamp,
    };

    match removed_recipients {
        Some(list) => upsert_removed_recipient(list, removed),
        None => *removed_recipients = Some(vec![removed]),
    }
    Ok(())
}

/// Merge an existing removed recipient history list into a target list.
pub fn merge_removed_history(
    target: &mut Option<Vec<RemovedRecipient>>,
    source: Option<&Vec<RemovedRecipient>>,
) {
    if let Some(old_removed) = source {
        match target {
            Some(new_list) => {
                dedup_removed_recipients(new_list);
                for removed in old_removed {
                    if new_list.iter().any(|existing| existing.kid == removed.kid) {
                        continue;
                    }
                    new_list.push(removed.clone());
                }
            }
            None => *target = Some(build_deduped_removed_recipients(old_removed)),
        }
    }
}

fn upsert_removed_recipient(list: &mut Vec<RemovedRecipient>, removed: RemovedRecipient) {
    if let Some(index) = list.iter().position(|existing| existing.kid == removed.kid) {
        list[index] = removed;
        dedup_removed_recipients(list);
        return;
    }

    list.push(removed);
}

fn dedup_removed_recipients(list: &mut Vec<RemovedRecipient>) {
    *list = build_unique_removed_recipients(list.drain(..));
}

fn build_deduped_removed_recipients(source: &[RemovedRecipient]) -> Vec<RemovedRecipient> {
    build_unique_removed_recipients(source.iter().cloned())
}

fn build_unique_removed_recipients(
    source: impl IntoIterator<Item = RemovedRecipient>,
) -> Vec<RemovedRecipient> {
    let removed_recipients = source.into_iter();
    let mut deduped = Vec::with_capacity(removed_recipients.size_hint().0);
    for removed in removed_recipients {
        if deduped
            .iter()
            .any(|existing: &RemovedRecipient| existing.kid == removed.kid)
        {
            continue;
        }
        deduped.push(removed);
    }
    deduped
}
