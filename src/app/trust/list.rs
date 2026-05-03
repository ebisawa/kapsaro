// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust list use case.

use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::load_optional_trust_store_for_member;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::KnownKey;
use crate::Result;

#[derive(Debug, Clone)]
pub(crate) struct TrustListItem {
    pub(crate) kid: Kid,
    pub(crate) member_handle: MemberHandle,
    pub(crate) approved_at: String,
    pub(crate) approved_via: String,
}

/// Result of trust list command.
#[derive(Debug)]
pub(crate) struct TrustListResult {
    pub(crate) items: Vec<TrustListItem>,
    pub(crate) warnings: Vec<String>,
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

/// List known_keys from the local trust store.
pub(crate) fn list_known_keys(
    options: &CommonCommandOptions,
    member_handle: &str,
) -> Result<TrustListResult> {
    let (_, loaded) = load_optional_trust_store_for_member(options, member_handle)?;
    let Some(loaded) = loaded else {
        return Ok(TrustListResult {
            items: Vec::new(),
            warnings: Vec::new(),
        });
    };

    let items = loaded
        .protected
        .known_keys
        .iter()
        .map(TrustListItem::from)
        .collect();

    Ok(TrustListResult {
        items,
        warnings: loaded.warnings,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/app_trust_list_test.rs"]
mod tests;
