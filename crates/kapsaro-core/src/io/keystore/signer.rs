// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signer public key loading utilities.

use crate::io::keystore::public_key_source::PublicKeySource;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::Result;

/// Load the signer's public key for embedding in signatures.
///
/// The key id is the one the signature will name, so the public half is read
/// under that id rather than under whichever key the member currently uses.
pub fn load_signer_public_key(
    pub_key_source: &dyn PublicKeySource,
    member_handle: &MemberHandle,
    kid: &Kid,
) -> Result<PublicKey> {
    pub_key_source.load_public_key_for_kid(member_handle, kid)
}
