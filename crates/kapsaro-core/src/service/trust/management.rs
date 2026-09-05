// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust remove / trust purge use cases.

use crate::feature::trust::known_keys::{purge_known_keys, remove_known_key};
use crate::feature::trust::purge::{collect_purge_candidates, ApprovalRecord};
use crate::feature::trust::recipient_sets::{purge_recipient_sets, remove_recipient_set};
use crate::feature::trust::store_mutation::{
    build_trust_store_not_found_error, TrustStoreMutation,
};
use crate::model::trust_store::TrustStoreProtected;
use crate::service::trust::store::{
    execute_trust_store_mutation_with_session,
    execute_trust_store_mutation_with_session_preparation_reporting_resign,
    observe_session_trust_store,
};
use crate::service::trust::transaction::TrustStorePreparation;
use crate::service::trust::types::RemovedKnownKey;
use crate::service::trust::TrustCommandSession;
use crate::Result;
use time::OffsetDateTime;

use super::list::{RecipientSetListItem, TrustListItem};

/// Purge candidates bound to the exact trust store observation shown for review.
///
/// The cut-off travels with the candidates rather than being supplied again at
/// execution: the set the operator agreed to is the set that cut-off selected,
/// and a second copy of it could disagree. The observation travels with them
/// too, so the write-back commits against the same bytes and verifies with the
/// signer keys read for the review.
pub struct ReviewedPurgeCandidates<'a, T> {
    pub items: Vec<T>,
    session: &'a TrustCommandSession,
    prepared: TrustStorePreparation,
    older_than: OffsetDateTime,
}

impl<T: std::fmt::Debug> std::fmt::Debug for ReviewedPurgeCandidates<'_, T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReviewedPurgeCandidates")
            .field("items", &self.items)
            .field("older_than", &self.older_than)
            .finish_non_exhaustive()
    }
}

/// Remove a known key by kid and re-sign the trust store.
pub fn remove_known_key_command(
    session: &TrustCommandSession,
    kid: &str,
) -> Result<RemovedKnownKey> {
    execute_trust_store_mutation_with_session(session, |protected| {
        let removed = remove_known_key(&mut protected.known_keys, kid)?;
        Ok(TrustStoreMutation {
            value: RemovedKnownKey {
                member_handle: removed.subject_handle,
                kid: removed.kid,
            },
            changed: true,
        })
    })
}

/// Remove a recipient set approval by sid and re-sign the trust store.
pub fn remove_recipient_set_command(session: &TrustCommandSession, sid: &str) -> Result<String> {
    execute_trust_store_mutation_with_session(session, |protected| {
        let removed = remove_recipient_set(&mut protected.recipient_sets, sid)?;
        Ok(TrustStoreMutation {
            value: removed.sid,
            changed: true,
        })
    })
}

/// List purge candidates (entries older than threshold).
pub fn list_purge_candidates<'a>(
    session: &'a TrustCommandSession,
    older_than_timestamp: OffsetDateTime,
) -> Result<ReviewedPurgeCandidates<'a, TrustListItem>> {
    list_trust_store_purge_candidates(session, older_than_timestamp, |protected| {
        &protected.known_keys
    })
}

/// List recipient set purge candidates (entries older than threshold).
pub fn list_recipient_set_purge_candidates<'a>(
    session: &'a TrustCommandSession,
    older_than_timestamp: OffsetDateTime,
) -> Result<ReviewedPurgeCandidates<'a, RecipientSetListItem>> {
    list_trust_store_purge_candidates(session, older_than_timestamp, |protected| {
        &protected.recipient_sets
    })
}

fn list_trust_store_purge_candidates<'a, Record, Item, SelectRecords>(
    session: &'a TrustCommandSession,
    older_than_timestamp: OffsetDateTime,
    select_records: SelectRecords,
) -> Result<ReviewedPurgeCandidates<'a, Item>>
where
    Record: ApprovalRecord,
    Item: for<'r> From<&'r Record>,
    SelectRecords: FnOnce(&TrustStoreProtected) -> &[Record],
{
    // A purge reports what it is about to remove, so an absent store is a
    // failure rather than an empty candidate list. The listing is the
    // operator's last look at the store before it is cut down, so a store that
    // cannot be verified here still reaches the reset route.
    let observed = observe_session_trust_store(session)?;
    let protected = &observed
        .stored()
        .ok_or_else(|| build_trust_store_not_found_error(session.owner().as_str()))?
        .protected;

    let items = collect_purge_candidates(select_records(protected), older_than_timestamp)?
        .into_iter()
        .map(Item::from)
        .collect();

    Ok(ReviewedPurgeCandidates {
        items,
        session,
        prepared: observed.into_prepared(),
        older_than: older_than_timestamp,
    })
}

/// What executing a purge did to the stored trust document.
///
/// `judge_trust_store_write` re-signs the store under the current key even
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
    reviewed: &ReviewedPurgeCandidates<'_, TrustListItem>,
) -> Result<PurgeOutcome> {
    let (removed, resigned) =
        execute_trust_store_mutation_with_session_preparation_reporting_resign(
            reviewed.session,
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
    reviewed: &ReviewedPurgeCandidates<'_, RecipientSetListItem>,
) -> Result<PurgeOutcome> {
    let (removed, resigned) =
        execute_trust_store_mutation_with_session_preparation_reporting_resign(
            reviewed.session,
            &reviewed.prepared,
            |protected| {
                let removed =
                    purge_recipient_sets(&mut protected.recipient_sets, reviewed.older_than)?;
                let count = removed.len();
                Ok(TrustStoreMutation {
                    value: count,
                    changed: count > 0,
                })
            },
        )?;
    Ok(PurgeOutcome { removed, resigned })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_trust_management_test.rs"]
mod service_trust_management_test;
