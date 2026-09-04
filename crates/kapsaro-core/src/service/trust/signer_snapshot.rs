// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Reads the one signer key a trust store signature names, before any trust lock.
//! Keeps the keystore access out of the pure snapshot the verification rules use.

use crate::feature::trust::signer_keys::{build_unusable_signer_key_error, SignerKeySnapshot};
use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::Result;
use std::path::Path;

/// Read the public half of the key `kid` names, before any trust lock.
///
/// `kid` is `None` when there is no document to verify, or when the one there
/// is names its key in a form that identifies none. A key the keystore does not
/// hold contributes nothing: the signature naming it is then reported as a
/// signer key that is unavailable, which is the condition restoring that one
/// document repairs.
pub(crate) fn load_signer_key_snapshot(
    keystore: &KeystoreAccess,
    owner: &MemberHandle,
    kid: Option<&Kid>,
) -> Result<SignerKeySnapshot> {
    let keystore_root = keystore.root().to_path_buf();
    let key = match kid {
        Some(kid) => load_signer_key(keystore, &keystore_root, owner, kid)?
            .map(|public_key| (kid.clone(), public_key)),
        None => None,
    };
    Ok(SignerKeySnapshot::new(owner.clone(), keystore_root, key))
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

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_trust_signer_snapshot_test.rs"]
mod service_trust_signer_snapshot_test;
