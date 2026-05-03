// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! PrivateKey verification helpers.
//!
//! PrivateKey is authenticated via AEAD with AAD derived from `protected`, and its plaintext key
//! material is validated separately. This module adds an additional invariant check for keystore
//! usage: the PrivateKey stored under `keys/<member_handle>/<kid>/private.json` should correspond to
//! the PublicKey stored under the same directory.

use crate::model::private_key::PrivateKey;
use crate::model::public_key::PublicKey;
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, Result};

/// Verify that a PrivateKey document matches its corresponding PublicKey document.
///
/// This is intended for local keystore invariant checks (pairing correctness).
pub fn verify_private_key_matches_public_key(
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<()> {
    if private_key.protected.subject_handle != public_key.protected.subject_handle {
        return Err(Error::build_verification_error(
            "V-PRIVATEKEY-PUBKEY-MISMATCH",
            format!(
                "member_handle mismatch: private.protected.subject_handle '{}' != public.protected.subject_handle '{}'",
                private_key.protected.subject_handle, public_key.protected.subject_handle
            ),
        ));
    }

    if private_key.protected.kid != public_key.protected.kid {
        return Err(Error::build_verification_error(
            "V-PRIVATEKEY-PUBKEY-MISMATCH",
            format!(
                "kid mismatch: private.protected.kid '{}' != public.protected.kid '{}'",
                format_kid_display_lossy(&private_key.protected.kid),
                format_kid_display_lossy(&public_key.protected.kid)
            ),
        ));
    }

    // Note: timestamps like created_at/expires_at are intentionally not checked here.
    // They are authenticated within each document, but different generation/encryption steps
    // may legitimately set slightly different timestamps across PublicKey and PrivateKey.

    Ok(())
}
