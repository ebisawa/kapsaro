// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH key derivation for PrivateKey protection

use crate::crypto::kdf;
use crate::crypto::types::data::{Ikm, Info};
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::{HkdfSalt, PrivateKeyIkmSalt};
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identifiers::context;
use crate::support::kid::kid_display_lossy;
use crate::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::debug;

const NON_DETERMINISTIC_SIGNATURE_MESSAGE: &str =
    "Non-deterministic signature detected: same input produced different signatures";

/// Build sign_message for SSH signature.
pub fn build_sign_message(ikm_salt_b64: &str) -> String {
    format!(
        "{}\n{}",
        context::SSH_KEY_PROTECTION_SIGN_MESSAGE_PREFIX_V5,
        ikm_salt_b64
    )
}

/// Generate a random IKM salt for SSH-based key derivation.
pub fn generate_ikm_salt() -> PrivateKeyIkmSalt {
    let mut salt_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut salt_bytes);
    PrivateKeyIkmSalt::new(salt_bytes)
}

/// Generate a random HKDF salt for SSH-based key derivation.
pub fn generate_hkdf_salt() -> HkdfSalt {
    let mut salt_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut salt_bytes);
    HkdfSalt::new(salt_bytes)
}

/// Derive encryption key for a PrivateKey using SSH signature
pub fn derive_key_from_ssh(
    kid: &str,
    ikm_salt_b64: &str,
    hkdf_salt: &HkdfSalt,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    debug: bool,
) -> Result<XChaChaKey> {
    let message = build_sign_message(ikm_salt_b64);
    if debug {
        debug!(
            "[CRYPTO] SSH: sign_for_ikm x2 determinism check (kid: {})",
            kid_display_lossy(kid)
        );
    }
    let raw_sig = backend
        .sign_deterministic_for_ikm(ssh_pubkey, message.as_bytes())
        .map_err(map_determinism_error)?;
    if debug {
        debug!(
            "[CRYPTO] HKDF-SHA256: private key enc key derivation (kid: {})",
            kid_display_lossy(kid)
        );
    }
    let ikm = Ikm::from(&raw_sig.as_bytes()[..]);
    let info = Info::from_string(&format!(
        "{}:{}",
        context::SSH_PRIVATE_KEY_ENC_INFO_PREFIX_V5,
        kid
    ));
    let cek = kdf::expand_to_array(&ikm, Some(hkdf_salt), &info)?;
    XChaChaKey::from_slice(cek.as_bytes())
}

fn map_determinism_error(error: crate::Error) -> crate::Error {
    if error
        .to_string()
        .contains(NON_DETERMINISTIC_SIGNATURE_MESSAGE)
    {
        return crate::Error::Crypto {
            message: "W_SSH_NONDETERMINISTIC: SSH signature is non-deterministic".into(),
            source: None,
        };
    }

    error
}
