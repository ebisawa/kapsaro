// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust remove / trust purge use cases.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::{
    load_optional_trust_store_for_member, mutate_trust_store_with_execution, TrustStoreMutation,
    TrustStoreMutationMode,
};
use crate::app::trust::types::TrustMutationResult;
use crate::feature::trust::known_keys::{purge_known_keys, remove_known_key};
use crate::{Error, Result};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::list::{TrustListItem, TrustListResult};

pub(crate) type RemoveKnownKeyResult = TrustMutationResult<String>;
pub(crate) type PurgeKnownKeysResult = TrustMutationResult<usize>;

/// Remove a known key by kid and re-sign the trust store.
pub(crate) fn remove_known_key_command(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    kid: &str,
    debug: bool,
) -> Result<RemoveKnownKeyResult> {
    mutate_trust_store_with_execution(
        options,
        execution,
        TrustStoreMutationMode::ExistingRequired,
        debug,
        |protected| {
            let removed = remove_known_key(&mut protected.known_keys, kid)?;
            Ok(TrustStoreMutation {
                value: removed.member_id,
                changed: true,
            })
        },
    )
}

/// List purge candidates (entries older than threshold).
pub(crate) fn list_purge_candidates(
    options: &CommonCommandOptions,
    member_id: &str,
    older_than_timestamp: OffsetDateTime,
) -> Result<TrustListResult> {
    let (_, loaded) = load_optional_trust_store_for_member(options, member_id)?;
    let loaded = loaded.ok_or_else(|| Error::NotFound {
        message: format!("Trust store not found for '{}'", member_id),
    })?;

    let items = loaded
        .protected
        .known_keys
        .iter()
        .filter_map(|k| match parse_approved_at(&k.approved_at) {
            Ok(approved_at) if approved_at < older_than_timestamp => {
                Some(Ok(TrustListItem::from(k)))
            }
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(TrustListResult {
        items,
        warnings: loaded.warnings,
    })
}

/// Execute purge: remove old entries and re-sign.
pub(crate) fn execute_purge(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    older_than_timestamp: OffsetDateTime,
    debug: bool,
) -> Result<PurgeKnownKeysResult> {
    mutate_trust_store_with_execution(
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

fn parse_approved_at(ts: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(ts, &Rfc3339).map_err(|e| Error::Parse {
        message: format!("Failed to parse known_keys[].approved_at '{}': {}", ts, e),
        source: Some(Box::new(e)),
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/app_trust_management_test.rs"]
mod tests;
