// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Which stored approvals a cut-off date selects, for listing and for removal.
//! One rule so the candidates an operator is shown are the entries a purge removes.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::model::trust_store::{KnownKey, RecipientSetRecord};
use crate::{Error, Result};

/// A stored approval a purge can select by its recorded time.
pub trait ApprovalRecord {
    /// How the timestamp is named in the stored document, for reporting.
    const APPROVED_AT_FIELD: &'static str;

    fn approved_at(&self) -> &str;
}

impl ApprovalRecord for KnownKey {
    const APPROVED_AT_FIELD: &'static str = "known_keys[].approved_at";

    fn approved_at(&self) -> &str {
        &self.approved_at
    }
}

impl ApprovalRecord for RecipientSetRecord {
    const APPROVED_AT_FIELD: &'static str = "recipient_sets[].approved_at";

    fn approved_at(&self) -> &str {
        &self.approved_at
    }
}

/// The records a cut-off selects, in the order they are stored.
///
/// The cut-off is exclusive: an approval recorded exactly at it is kept, so a
/// run that names the moment of an approval never removes it.
pub fn collect_purge_candidates<R: ApprovalRecord>(
    records: &[R],
    older_than: OffsetDateTime,
) -> Result<Vec<&R>> {
    let mut candidates = Vec::new();
    for record in records {
        if parse_approved_at::<R>(record.approved_at())? < older_than {
            candidates.push(record);
        }
    }
    Ok(candidates)
}

/// Remove the records the cut-off selects and hand them back.
pub fn purge_records<R: ApprovalRecord>(
    records: &mut Vec<R>,
    older_than: OffsetDateTime,
) -> Result<Vec<R>> {
    let mut removed = Vec::new();
    let mut retained = Vec::with_capacity(records.len());
    for record in records.drain(..) {
        if parse_approved_at::<R>(record.approved_at())? < older_than {
            removed.push(record);
        } else {
            retained.push(record);
        }
    }
    *records = retained;
    Ok(removed)
}

fn parse_approved_at<R: ApprovalRecord>(approved_at: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(approved_at, &Rfc3339).map_err(|e| {
        Error::build_parse_error_with_source(
            format!(
                "Failed to parse {} '{}': {}",
                R::APPROVED_AT_FIELD,
                approved_at,
                e
            ),
            e,
        )
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_trust_purge_test.rs"]
mod feature_trust_purge_test;
