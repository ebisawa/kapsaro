// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public key loading operations for multiple recipients
//!
//! Provides functions to load public keys for a list of member handles.

use crate::io::keystore::helpers::resolve_kid;
use crate::io::keystore::storage::load_public_key;
use crate::model::public_key::PublicKey;
use crate::Result;
use std::path::Path;

/// Load public keys for a list of recipients from keystore
///
/// # Arguments
/// * `keystore_root` - Path to keystore root directory
/// * `recipients` - List of member handles to load public keys for
///
/// # Returns
/// Vector of PublicKey documents, one for each recipient
///
/// # Errors
/// Returns error if any recipient's public key cannot be loaded or resolved
pub fn load_public_keys_for_member_handles(
    keystore_root: &Path,
    recipients: &[String],
) -> Result<Vec<PublicKey>> {
    recipients
        .iter()
        .map(|recipient_handle| {
            let kid = resolve_kid(keystore_root, recipient_handle, None)?;
            load_public_key(keystore_root, recipient_handle, &kid)
        })
        .collect()
}
