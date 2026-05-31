// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signer public key loading utilities.

use crate::io::keystore::public_key_source::PublicKeySource;
use crate::model::public_key::PublicKey;
use crate::Result;

/// Load signer's public key for embedding in signatures.
pub fn load_signer_public_key(
    pub_key_source: &dyn PublicKeySource,
    member_handle: &str,
) -> Result<PublicKey> {
    pub_key_source.load_public_key(member_handle)
}
