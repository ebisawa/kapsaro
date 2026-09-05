// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient-set trust-store record mutations.
//! Applies upsert, remove, and timestamp-based purge operations to record lists.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::feature::trust::purge::purge_records;
use crate::model::trust_store::RecipientSetRecord;
use crate::{Error, Result};

use super::record::ArtifactRecipientSet;

/// Approve one recipient set and report whether that moved the records.
///
/// `approved_at` takes part in the comparison like every other field, so an
/// approval of the same recipients at a later time is a change: the stored
/// timestamp names the approval that is current rather than the first one.
///
/// The record the sid names is replaced whole rather than merged into, so
/// nothing of the stored approval survives this call. Whether replacing it is
/// safe is settled by what the caller binds the write to.
pub fn upsert_recipient_set(
    records: &mut Vec<RecipientSetRecord>,
    current: ArtifactRecipientSet,
    approved_at: String,
) -> bool {
    let sid = current.sid_string();
    let candidate = current.into_record(approved_at);
    if let Some(record) = records.iter_mut().find(|record| record.sid == sid) {
        if *record == candidate {
            return false;
        }
        *record = candidate;
        return true;
    }
    records.push(candidate);
    true
}

pub fn remove_recipient_set(
    records: &mut Vec<RecipientSetRecord>,
    sid: &str,
) -> Result<RecipientSetRecord> {
    let sid = Uuid::parse_str(sid)
        .map(|sid| sid.to_string())
        .map_err(|e| Error::build_invalid_sid_error(sid, e))?;
    let pos = records
        .iter()
        .position(|record| record.sid == sid)
        .ok_or_else(|| {
            Error::build_not_found_error(format!("sid '{}' not found in recipient_sets", sid))
        })?;
    Ok(records.remove(pos))
}

pub fn purge_recipient_sets(
    records: &mut Vec<RecipientSetRecord>,
    older_than: OffsetDateTime,
) -> Result<Vec<RecipientSetRecord>> {
    purge_records(records, older_than)
}
