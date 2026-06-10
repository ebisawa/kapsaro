// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust remove / trust purge use cases.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::{
    build_trust_store_not_found_error, execute_trust_store_mutation_with_execution,
    load_optional_trust_store_for_member, TrustStoreMutation, TrustStoreMutationMode,
};
use crate::app::trust::types::{RemovedKnownKey, TrustMutationResult};
use crate::feature::trust::known_keys::{purge_known_keys, remove_known_key};
use crate::feature::trust::recipient_sets::{purge_recipient_sets, remove_recipient_set};
use crate::model::trust_store::{KnownKey, RecipientSetRecord, TrustStoreProtected};
use crate::{Error, Result};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::list::{RecipientSetListItem, RecipientSetListResult, TrustListItem, TrustListResult};

pub type RemoveKnownKeyResult = TrustMutationResult<RemovedKnownKey>;
pub type PurgeKnownKeysResult = TrustMutationResult<usize>;
pub type RemoveRecipientSetResult = TrustMutationResult<String>;
pub type PurgeRecipientSetsResult = TrustMutationResult<usize>;

/// Remove a known key by kid and re-sign the trust store.
pub fn remove_known_key_command(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    kid: &str,
    debug: bool,
) -> Result<RemoveKnownKeyResult> {
    execute_trust_store_mutation_with_execution(
        options,
        execution,
        TrustStoreMutationMode::ExistingRequired,
        debug,
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
    debug: bool,
) -> Result<RemoveRecipientSetResult> {
    execute_trust_store_mutation_with_execution(
        options,
        execution,
        TrustStoreMutationMode::ExistingRequired,
        debug,
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
    options: &CommonCommandOptions,
    member_handle: &str,
    older_than_timestamp: OffsetDateTime,
) -> Result<TrustListResult> {
    let candidates = list_trust_store_purge_candidates(
        options,
        member_handle,
        older_than_timestamp,
        |protected| &protected.known_keys,
    )?;

    Ok(TrustListResult {
        items: candidates.items,
        warnings: candidates.warnings,
    })
}

/// List recipient set purge candidates (entries older than threshold).
pub fn list_recipient_set_purge_candidates(
    options: &CommonCommandOptions,
    member_handle: &str,
    older_than_timestamp: OffsetDateTime,
) -> Result<RecipientSetListResult> {
    let candidates = list_trust_store_purge_candidates(
        options,
        member_handle,
        older_than_timestamp,
        |protected| &protected.recipient_sets,
    )?;

    Ok(RecipientSetListResult {
        items: candidates.items,
        warnings: candidates.warnings,
    })
}

struct PurgeCandidateList<T> {
    items: Vec<T>,
    warnings: Vec<String>,
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
    options: &CommonCommandOptions,
    member_handle: &str,
    older_than_timestamp: OffsetDateTime,
    select_records: SelectRecords,
) -> Result<PurgeCandidateList<Record::Item>>
where
    Record: PurgeCandidateRecord,
    SelectRecords: FnOnce(&TrustStoreProtected) -> &[Record],
{
    let (_, loaded) = load_optional_trust_store_for_member(options, member_handle)?;
    let loaded = loaded.ok_or_else(|| build_trust_store_not_found_error(member_handle))?;

    let items = select_records(&loaded.protected)
        .iter()
        .filter_map(|record| match parse_approved_at(record.approved_at()) {
            Ok(approved_at) if approved_at < older_than_timestamp => Some(Ok(record.to_item())),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(PurgeCandidateList {
        items,
        warnings: loaded.warnings,
    })
}

/// Execute purge: remove old entries and re-sign.
pub fn execute_purge(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    older_than_timestamp: OffsetDateTime,
    debug: bool,
) -> Result<PurgeKnownKeysResult> {
    execute_trust_store_mutation_with_execution(
        options,
        execution,
        TrustStoreMutationMode::ExistingRequired,
        debug,
        |protected| {
            let removed = purge_known_keys(&mut protected.known_keys, older_than_timestamp)?;
            let count = removed.len();
            Ok(TrustStoreMutation {
                value: count,
                changed: count > 0,
            })
        },
    )
}

/// Execute recipient set purge: remove old entries and re-sign.
pub fn execute_recipient_set_purge(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    older_than_timestamp: OffsetDateTime,
    debug: bool,
) -> Result<PurgeRecipientSetsResult> {
    execute_trust_store_mutation_with_execution(
        options,
        execution,
        TrustStoreMutationMode::ExistingRequired,
        debug,
        |protected| {
            let removed =
                purge_recipient_sets(&mut protected.recipient_sets, older_than_timestamp)?;
            let count = removed.len();
            Ok(TrustStoreMutation {
                value: count,
                changed: count > 0,
            })
        },
    )
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
