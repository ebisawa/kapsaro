// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore member-oriented lookup helpers.
//! Resolves the active key document and the sole member handle a keystore holds.

use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::Result;

/// Active key document lookup result.
pub struct ActiveKeyDocument {
    pub kid: Kid,
    pub public_key: PublicKey,
}

/// Load member_handle from keystore if exactly one exists.
pub(crate) fn load_single_member_handle_from_keystore(
    access: &KeystoreAccess,
) -> Result<Option<MemberHandle>> {
    let members = access.list_members()?;
    match members.len() {
        1 => Ok(members.into_iter().next()),
        _ => Ok(None),
    }
}

/// Load the active public key document for a member when the private key still exists.
pub(crate) fn find_active_key_document(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
) -> Result<Option<ActiveKeyDocument>> {
    access
        .load_active_public_key_with_private(member_handle)
        .map(|active| active.map(|(kid, public_key)| ActiveKeyDocument { kid, public_key }))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_keystore_member_test.rs"]
mod io_keystore_member_test;
