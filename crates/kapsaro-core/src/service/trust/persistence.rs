// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! What one trust store mutation writes through, and how the write lands on disk.
//! The transaction holds the lock; this signs the result and saves it.

use crate::feature::context::crypto::VerifiedSigningContext;
use crate::feature::trust::signature::sign_trust_store;
use crate::feature::trust::store_mutation::TrustStoreWrite;
use crate::io::trust::store::save_trust_store_at;
use crate::model::identity::MemberHandle;
use crate::model::trust_store::TrustStoreProtected;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock::ExclusiveLockedDir;
use crate::support::fs::relative::{DirectoryFd, OpenDir};
use crate::support::time::generate_current_timestamp;
use crate::Result;
use std::path::Path;
use tracing::debug;

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

/// Persist the mutated store the way the write decision calls for.
///
/// Only a content change moves `updated_at`: that field states when the
/// approvals last moved, and a signature handed to another key says nothing
/// about them.
pub(crate) fn save_trust_store_for_write_at(
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
