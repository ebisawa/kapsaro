// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! The trust store content one mutation acts on, and whether it has to be written.
//! Pure rules only: the transaction that drives them decides when they run.

use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::TrustStoreProtected;
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::support::time::generate_current_timestamp;
use crate::{Error, Result};

pub(crate) struct TrustStoreState {
    pub(crate) protected: TrustStoreProtected,
    /// Key named by the signature of the document this state was loaded from.
    /// Absent for a store that has not been written yet.
    pub(crate) signer_kid: Option<Kid>,
}

/// What persisting a mutation has to do with the stored document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustStoreWrite {
    /// The stored document already says what this command would write.
    Skip,
    /// The content is unchanged but a different key has to carry the signature.
    Resign,
    /// The content changed and is written with a fresh timestamp.
    Save,
}

pub(crate) struct TrustStoreMutation<T> {
    pub(crate) value: T,
    pub(crate) changed: bool,
}

pub(crate) fn build_trust_store_not_found_error(owner_handle: &str) -> Error {
    Error::build_not_found_error(format!("Trust store not found for '{}'", owner_handle))
}

/// Decide whether the stored trust store has to be written again.
///
/// A signature made by a key that is no longer the signing key keeps the store
/// tied to that key's continued presence, so the signer alone is reason enough
/// to write even when nothing in the content moved.
pub(crate) fn judge_trust_store_write(
    changed: bool,
    stored_signer_kid: Option<&str>,
    current_signer_kid: &str,
) -> TrustStoreWrite {
    if changed {
        return TrustStoreWrite::Save;
    }
    match stored_signer_kid {
        Some(stored) if stored != current_signer_kid => TrustStoreWrite::Resign,
        _ => TrustStoreWrite::Skip,
    }
}

pub(crate) fn build_empty_trust_store(owner: &MemberHandle) -> Result<TrustStoreState> {
    let now = generate_current_timestamp()?;
    Ok(TrustStoreState {
        protected: TrustStoreProtected {
            format: LOCAL_TRUST_V1.to_string(),
            owner_handle: owner.to_string(),
            created_at: now.clone(),
            updated_at: now,
            known_keys: Vec::new(),
            recipient_sets: Vec::new(),
        },
        signer_kid: None,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_trust_store_mutation_test.rs"]
mod feature_trust_store_mutation_test;
