// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust list use case.

use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::load_optional_trust_store_for_member;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::{KnownKey, RecipientSetRecord, TrustStoreProtected};
use crate::Result;

#[derive(Debug, Clone)]
pub struct TrustListItem {
    pub kid: Kid,
    pub member_handle: MemberHandle,
    pub approved_at: String,
    pub approved_via: String,
}

#[derive(Debug, Clone)]
pub struct RecipientSetListItem {
    pub sid: String,
    pub recipient_kids: Vec<String>,
    pub recipient_set_hash: String,
    pub approved_at: String,
    pub approved_via: String,
}

/// Result of trust list command.
#[derive(Debug)]
pub struct TrustListResult {
    pub items: Vec<TrustListItem>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct RecipientSetListResult {
    pub items: Vec<RecipientSetListItem>,
    pub warnings: Vec<String>,
}

struct TrustStoreListEntries<T> {
    items: Vec<T>,
    warnings: Vec<String>,
}

impl From<&KnownKey> for TrustListItem {
    fn from(known_key: &KnownKey) -> Self {
        Self {
            kid: Kid::try_from(known_key.kid.clone()).expect("known key kid must be valid"),
            member_handle: MemberHandle::try_from(known_key.subject_handle.clone())
                .expect("known key member_handle must be valid"),
            approved_at: known_key.approved_at.clone(),
            approved_via: known_key.approved_via.to_string(),
        }
    }
}

impl From<&RecipientSetRecord> for RecipientSetListItem {
    fn from(record: &RecipientSetRecord) -> Self {
        Self {
            sid: record.sid.clone(),
            recipient_kids: record.recipient_kids.clone(),
            recipient_set_hash: record.recipient_set_hash.clone(),
            approved_at: record.approved_at.clone(),
            approved_via: record.approved_via.to_string(),
        }
    }
}

/// List known_keys from the local trust store.
pub fn list_known_keys(
    options: &CommonCommandOptions,
    member_handle: &str,
) -> Result<TrustListResult> {
    let entries = load_trust_store_list_entries(options, member_handle, |protected| {
        protected
            .known_keys
            .iter()
            .map(TrustListItem::from)
            .collect()
    })?;
    Ok(TrustListResult {
        items: entries.items,
        warnings: entries.warnings,
    })
}

/// List recipient_sets from the local trust store.
pub fn list_recipient_sets(
    options: &CommonCommandOptions,
    member_handle: &str,
) -> Result<RecipientSetListResult> {
    let entries = load_trust_store_list_entries(options, member_handle, |protected| {
        protected
            .recipient_sets
            .iter()
            .map(RecipientSetListItem::from)
            .collect()
    })?;
    Ok(RecipientSetListResult {
        items: entries.items,
        warnings: entries.warnings,
    })
}

fn load_trust_store_list_entries<T>(
    options: &CommonCommandOptions,
    member_handle: &str,
    build_items: impl FnOnce(&TrustStoreProtected) -> Vec<T>,
) -> Result<TrustStoreListEntries<T>> {
    let (_, loaded) = load_optional_trust_store_for_member(options, member_handle)?;
    let Some(loaded) = loaded else {
        return Ok(TrustStoreListEntries {
            items: Vec::new(),
            warnings: Vec::new(),
        });
    };
    Ok(TrustStoreListEntries {
        items: build_items(&loaded.protected),
        warnings: loaded.warnings,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_list_test.rs"]
mod tests;
