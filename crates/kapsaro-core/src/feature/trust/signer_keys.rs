// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! The one public key a trust store signature names, read in a single pass.
//! Lets trust store verification run without reaching into the keystore again.

use crate::error::TRUST_STORE_RESET_REQUIRED_RECOVERY;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::paths::get_public_key_file_path_from_root;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::model::trust_store::TrustStoreDocument;
use crate::support::path::format_finding_path;
use crate::{Error, Result};
use std::fmt;
use std::path::{Path, PathBuf};

/// The signer key one document named, observed under a single shared lock.
///
/// Verification needs the signer's public half and nothing else, so taking it
/// once lets the trust directory's exclusive lock be acquired afterwards
/// without the member lock still being held.
///
/// Only the named key is read. Every other key the member holds is irrelevant
/// to this signature, and a stale key whose document no longer parses would
/// otherwise fail every command that consults the trust store.
#[derive(Clone)]
pub(crate) struct SignerKeySnapshot {
    owner: MemberHandle,
    keystore_root: PathBuf,
    key: Option<(Kid, PublicKey)>,
}

/// Report the snapshot by the key it found.
///
/// What a snapshot is is the one key a signature named, so that is what is
/// written. Deriving this instead would replay a whole public key document and
/// the local path it was read from into every enclosing type's `{:?}`.
impl fmt::Debug for SignerKeySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.key {
            Some((kid, _)) => write!(f, "SignerKeySnapshot({})", kid),
            None => f.write_str("SignerKeySnapshot(no key)"),
        }
    }
}

impl SignerKeySnapshot {
    /// Read the public half of the key `kid` names, before any trust lock.
    ///
    /// `kid` is `None` when there is no document to verify, or when the one
    /// there is names its key in a form that identifies none. A key the
    /// keystore does not hold contributes nothing: the signature naming it is
    /// then reported as a signer key that is unavailable, which is the
    /// condition restoring that one document repairs.
    pub(crate) fn capture(
        keystore: &KeystoreAccess,
        owner: &MemberHandle,
        kid: Option<&Kid>,
    ) -> Result<Self> {
        let keystore_root = keystore.root().to_path_buf();
        let key = match kid {
            Some(kid) => load_signer_key(keystore, &keystore_root, owner, kid)?
                .map(|public_key| (kid.clone(), public_key)),
            None => None,
        };
        Ok(Self {
            owner: owner.clone(),
            keystore_root,
            key,
        })
    }

    /// The member whose key this snapshot holds.
    pub(crate) fn owner(&self) -> &MemberHandle {
        &self.owner
    }

    /// The keystore root the key was read from, for reporting only.
    pub(crate) fn keystore_root(&self) -> &Path {
        &self.keystore_root
    }

    /// The owner's public key with this `kid`, when the snapshot holds one.
    pub(crate) fn find(&self, kid: &Kid) -> Option<&PublicKey> {
        self.key
            .as_ref()
            .filter(|(candidate, _)| candidate == kid)
            .map(|(_, public_key)| public_key)
    }
}

/// The key a document's signature names, when the name identifies one.
///
/// `signature.kid` is untrusted text until the document verifies, so a name
/// that is not the canonical form a stored document carries resolves to no key
/// at all and the document is reported by verification rather than as a key the
/// keystore is missing. Reading it as canonical is what keeps the name the
/// signature was computed over out of the keystore lookup: a display form
/// normalized here would send the read after a key the stored bytes never
/// named.
pub(crate) fn document_signer_kid(doc: &TrustStoreDocument) -> Option<Kid> {
    Kid::from_canonical(doc.signature.kid.clone()).ok()
}

/// Read one signer key, reporting a failure the way its cause allows.
///
/// A key document that will not read back leaves the stored signature
/// unverifiable, so it takes the rule that carries the recovery route. An I/O
/// failure, a refused permission, or an unsafe path never reached the document
/// and says nothing about it: it travels as itself, so a fault that a `chmod`
/// or a retry clears is not answered with an offer to discard the approvals.
///
/// A key the keystore simply does not hold is no failure at all. It comes back
/// as no key, and verification is what names the signer key that is missing.
fn load_signer_key(
    keystore: &KeystoreAccess,
    keystore_root: &Path,
    owner: &MemberHandle,
    kid: &Kid,
) -> Result<Option<PublicKey>> {
    keystore.load_optional_public_key(owner, kid).map_err(|e| {
        if e.kind().is_content_failure() {
            build_unusable_signer_key_error(keystore_root, owner, kid, e)
        } else {
            e
        }
    })
}

/// Report a signer key document that read back as something unusable.
///
/// The failure is carried in as what it was — a parse, a schema mismatch, a
/// signature that did not verify — and stays that, gaining only the route that
/// gets past it.
fn build_unusable_signer_key_error(
    keystore_root: &Path,
    owner: &MemberHandle,
    kid: &Kid,
    cause: Error,
) -> Error {
    let message = format!(
        "Trust store signer key '{}' for member '{}' could not be read, so the stored approvals \
         cannot be verified: {}. {}",
        kid,
        owner,
        cause.format_user_message(),
        build_signer_key_recovery_hint(keystore_root, owner, kid)
    );
    cause
        .with_message(message)
        .with_recovery(TRUST_STORE_RESET_REQUIRED_RECOVERY)
}

/// The one route back to a verifying store once its signer key is unusable.
pub(crate) fn build_signer_key_recovery_hint(
    keystore_root: &Path,
    owner: &MemberHandle,
    kid: &Kid,
) -> String {
    let public_key_path = get_public_key_file_path_from_root(keystore_root, owner, kid);
    format!(
        "To keep them, restore the complete original document from a trusted backup or known-good \
         copy to '{}' with owner-only permissions, then run 'kapsaro trust resign --member-handle \
         {}'. If no trusted copy exists, reset the trust store and review the approvals again.",
        format_finding_path(&public_key_path),
        owner
    )
}

/// The same route, stated where there is no key to name.
///
/// The deletion prompt is one such place: it asks about the store rather than
/// about a key, and the operator has to be reminded that the approvals can be
/// kept before they answer it.
pub(crate) fn describe_signer_key_recovery_route(owner: &MemberHandle) -> String {
    format!(
        "Restoring the complete original public.json from a trusted backup or known-good copy with \
         owner-only permissions and running 'kapsaro trust resign --member-handle {}' keeps the \
         stored approvals. If no trusted copy exists, reset the trust store and review the \
         approvals again.",
        owner
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_trust_signer_keys_test.rs"]
mod feature_trust_signer_keys_test;
