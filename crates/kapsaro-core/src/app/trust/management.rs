// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust remove / trust purge use cases.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::{
    execute_trust_store_mutation_with_execution,
    execute_trust_store_mutation_with_preparation_reporting_resign, observe_execution_trust_store,
    TrustStoreWriteBinding,
};
use crate::app::trust::types::RemovedKnownKey;
use crate::feature::trust::known_keys::{purge_known_keys, remove_known_key};
use crate::feature::trust::recipient_sets::{purge_recipient_sets, remove_recipient_set};
use crate::feature::trust::store_mutation::{
    build_trust_store_not_found_error, TrustStoreMutation, TrustStoreMutationMode,
};
use crate::feature::trust::transaction::TrustStorePreparation;
use crate::model::trust_store::{KnownKey, RecipientSetRecord, TrustStoreProtected};
use crate::{Error, Result};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::list::{RecipientSetListItem, TrustListItem};

/// Purge candidates bound to the exact trust store observation shown for review.
///
/// The cut-off travels with the candidates rather than being supplied again at
/// execution: the set the operator agreed to is the set that cut-off selected,
/// and a second copy of it could disagree. The observation travels with them
/// too, so the write-back commits against the same bytes and verifies with the
/// signer keys read for the review.
#[derive(Debug)]
pub struct ReviewedPurgeCandidates<T> {
    pub items: Vec<T>,
    prepared: TrustStorePreparation,
    older_than: OffsetDateTime,
}

/// Remove a known key by kid and re-sign the trust store.
pub fn remove_known_key_command(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    kid: &str,
) -> Result<RemovedKnownKey> {
    execute_trust_store_mutation_with_execution(
        options,
        execution,
        TrustStoreMutationMode::ExistingRequired,
        TrustStoreWriteBinding::ObservedDocument,
        |protected| {
            let removed = remove_known_key(&mut protected.known_keys, kid)?;
            Ok(TrustStoreMutation {
                value: RemovedKnownKey {
                    member_handle: removed.subject_handle,
                    kid: removed.kid,
                },
                changed: true,
            })
        },
    )
}

/// Remove a recipient set approval by sid and re-sign the trust store.
pub fn remove_recipient_set_command(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    sid: &str,
) -> Result<String> {
    execute_trust_store_mutation_with_execution(
        options,
        execution,
        TrustStoreMutationMode::ExistingRequired,
        TrustStoreWriteBinding::ObservedDocument,
        |protected| {
            let removed = remove_recipient_set(&mut protected.recipient_sets, sid)?;
            Ok(TrustStoreMutation {
                value: removed.sid,
                changed: true,
            })
        },
    )
}

/// List purge candidates (entries older than threshold).
pub fn list_purge_candidates(
    execution: &ExecutionContext,
    older_than_timestamp: OffsetDateTime,
) -> Result<ReviewedPurgeCandidates<TrustListItem>> {
    list_trust_store_purge_candidates(execution, older_than_timestamp, |protected| {
        &protected.known_keys
    })
}

/// List recipient set purge candidates (entries older than threshold).
pub fn list_recipient_set_purge_candidates(
    execution: &ExecutionContext,
    older_than_timestamp: OffsetDateTime,
) -> Result<ReviewedPurgeCandidates<RecipientSetListItem>> {
    list_trust_store_purge_candidates(execution, older_than_timestamp, |protected| {
        &protected.recipient_sets
    })
}

trait PurgeCandidateRecord {
    type Item;

    fn approved_at(&self) -> &str;

    fn to_item(&self) -> Self::Item;
}

impl PurgeCandidateRecord for KnownKey {
    type Item = TrustListItem;

    fn approved_at(&self) -> &str {
        &self.approved_at
    }

    fn to_item(&self) -> Self::Item {
        TrustListItem::from(self)
    }
}

impl PurgeCandidateRecord for RecipientSetRecord {
    type Item = RecipientSetListItem;

    fn approved_at(&self) -> &str {
        &self.approved_at
    }

    fn to_item(&self) -> Self::Item {
        RecipientSetListItem::from(self)
    }
}

fn list_trust_store_purge_candidates<Record, SelectRecords>(
    execution: &ExecutionContext,
    older_than_timestamp: OffsetDateTime,
    select_records: SelectRecords,
) -> Result<ReviewedPurgeCandidates<Record::Item>>
where
    Record: PurgeCandidateRecord,
    SelectRecords: FnOnce(&TrustStoreProtected) -> &[Record],
{
    // A purge reports what it is about to remove, so an absent store is a
    // failure rather than an empty candidate list. The listing is the
    // operator's last look at the store before it is cut down, so a store that
    // cannot be verified here still reaches the reset route.
    let observed =
        observe_execution_trust_store(execution, TrustStoreMutationMode::ExistingRequired)?;
    let protected = &observed
        .stored()
        .ok_or_else(|| build_trust_store_not_found_error(execution.member_handle.as_str()))?
        .protected;

    let items = select_records(protected)
        .iter()
        .filter_map(|record| match parse_approved_at(record.approved_at()) {
            Ok(approved_at) if approved_at < older_than_timestamp => Some(Ok(record.to_item())),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ReviewedPurgeCandidates {
        items,
        prepared: observed.into_prepared(),
        older_than: older_than_timestamp,
    })
}

/// What executing a purge did to the stored trust document.
///
/// `resolve_trust_store_write` re-signs the store under the current key even
/// when a mutation changed nothing, so a purge that removed zero entries can
/// still produce a write. Reporting only `removed` would let that re-signing
/// ride along inside a purge report with nothing to show it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeOutcome {
    pub removed: usize,
    pub resigned: bool,
}

/// Execute purge: remove old entries and re-sign.
pub fn execute_purge(
    execution: &ExecutionContext,
    reviewed: &ReviewedPurgeCandidates<TrustListItem>,
) -> Result<PurgeOutcome> {
    let (removed, resigned) = execute_trust_store_mutation_with_preparation_reporting_resign(
        execution,
        TrustStoreMutationMode::ExistingRequired,
        &reviewed.prepared,
        |protected| {
            let removed = purge_known_keys(&mut protected.known_keys, reviewed.older_than)?;
            let count = removed.len();
            Ok(TrustStoreMutation {
                value: count,
                changed: count > 0,
            })
        },
    )?;
    Ok(PurgeOutcome { removed, resigned })
}

/// Execute recipient set purge: remove old entries and re-sign.
pub fn execute_recipient_set_purge(
    execution: &ExecutionContext,
    reviewed: &ReviewedPurgeCandidates<RecipientSetListItem>,
) -> Result<PurgeOutcome> {
    let (removed, resigned) = execute_trust_store_mutation_with_preparation_reporting_resign(
        execution,
        TrustStoreMutationMode::ExistingRequired,
        &reviewed.prepared,
        |protected| {
            let removed = purge_recipient_sets(&mut protected.recipient_sets, reviewed.older_than)?;
            let count = removed.len();
            Ok(TrustStoreMutation {
                value: count,
                changed: count > 0,
            })
        },
    )?;
    Ok(PurgeOutcome { removed, resigned })
}

fn parse_approved_at(ts: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(ts, &Rfc3339).map_err(|e| {
        Error::build_parse_error_with_source(
            format!("Failed to parse known_keys[].approved_at '{}': {}", ts, e),
            e,
        )
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_management_test.rs"]
mod tests;
