// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store mutation building blocks: what one write targets and how it lands.
//! The transaction that drives them decides which content they act on.

use crate::feature::context::crypto::VerifiedSigningContext;
use crate::feature::trust::signature::sign_trust_store;
use crate::io::trust::store::save_trust_store_at;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::TrustStoreProtected;
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock::ExclusiveLockedDir;
use crate::support::fs::relative::{DirectoryFd, OpenDir};
use crate::support::time::generate_current_timestamp;
use crate::{Error, Result};
use std::path::Path;
use tracing::debug;

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

/// One mutation's result together with how it reached the stored document.
pub(crate) struct TrustStoreMutationOutcome<T> {
    pub(crate) value: T,
    pub(crate) write: TrustStoreWrite,
    pub(crate) signer_kid: String,
}

#[derive(Clone, Copy)]
pub(crate) enum TrustStoreMutationMode {
    ExistingRequired,
    CreateIfMissing,
}

pub(crate) struct TrustStoreMutation<T> {
    pub(crate) value: T,
    pub(crate) changed: bool,
}

/// Everything one trust store mutation writes through.
///
/// No keystore capability appears here: the keys a commit verifies with are
/// read before the trust directory is locked and travel with the preparation.
pub(crate) struct TrustStoreMutationTarget<'a> {
    pub(crate) base: &'a AnchoredDir,
    pub(crate) trust_dir: &'a OpenDir,
    pub(crate) path: &'a Path,
    pub(crate) owner: &'a MemberHandle,
    pub(crate) mode: TrustStoreMutationMode,
    pub(crate) signing: &'a VerifiedSigningContext<'a>,
}

pub(crate) fn build_trust_store_not_found_error(owner_handle: &str) -> Error {
    Error::build_not_found_error(format!("Trust store not found for '{}'", owner_handle))
}

/// Decide whether the stored trust store has to be written again.
///
/// A signature made by a key that is no longer the signing key keeps the store
/// tied to that key's continued presence, so the signer alone is reason enough
/// to write even when nothing in the content moved.
pub(crate) fn resolve_trust_store_write(
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

/// Persist the mutated store the way the write decision calls for.
///
/// Only a content change moves `updated_at`: that field states when the
/// approvals last moved, and a signature handed to another key says nothing
/// about them.
pub(crate) fn save_resolved_trust_store_at(
    base: &dyn DirectoryFd,
    dir: &ExclusiveLockedDir<'_>,
    path: &Path,
    protected: &mut TrustStoreProtected,
    signing: &VerifiedSigningContext<'_>,
    write: TrustStoreWrite,
) -> Result<()> {
    match write {
        TrustStoreWrite::Skip => {
            debug!("[TRUST] trust store unchanged: path={}", path.display());
            Ok(())
        }
        TrustStoreWrite::Resign => {
            debug!(
                "[TRUST] re-sign trust store: path={} signer_kid={}",
                path.display(),
                signing.signer_kid()
            );
            save_signed_trust_store_at(base, dir, path, protected, signing)
        }
        TrustStoreWrite::Save => {
            protected.updated_at = generate_current_timestamp()?;
            debug!("[TRUST] save trust store: path={}", path.display());
            save_signed_trust_store_at(base, dir, path, protected, signing)
        }
    }
}

fn save_signed_trust_store_at(
    base: &dyn DirectoryFd,
    dir: &ExclusiveLockedDir<'_>,
    path: &Path,
    protected: &TrustStoreProtected,
    signing: &VerifiedSigningContext<'_>,
) -> Result<()> {
    let document = sign_trust_store(protected, signing.signing_key(), signing.signer_kid())?;
    save_trust_store_at(base, dir, path, &document)
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
mod tests;
