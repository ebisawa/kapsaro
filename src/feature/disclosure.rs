// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Disclosure history helpers shared across encrypted document features.

use crate::model::common::RemovedRecipient;
use crate::support::time::current_timestamp;
use crate::Result;

/// Add a recipient to the removed recipient history list.
pub fn add_to_removed_history(
    removed_recipients: &mut Option<Vec<RemovedRecipient>>,
    rid: &str,
    kid: &str,
) -> Result<()> {
    let timestamp = current_timestamp()?;
    let removed = RemovedRecipient {
        rid: rid.to_string(),
        kid: kid.to_string(),
        removed_at: timestamp,
    };

    match removed_recipients {
        Some(list) => list.push(removed),
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
            Some(new_list) => new_list.extend(old_removed.clone()),
            None => *target = Some(old_removed.clone()),
        }
    }
}
