// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! PrivateKey verification helpers.
//!
//! PrivateKey is authenticated via AEAD with AAD derived from `protected`.
//! This module also checks the local keystore PublicKey/PrivateKey pairing.

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
                "PrivateKey subject does not match PublicKey subject.\n\
                 Private subject: {}\n\
                 Public subject: {}",
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
