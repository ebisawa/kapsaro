// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH key derivation for PrivateKey protection

use crate::crypto::kdf;
use crate::crypto::rng::fill_random_array;
use crate::crypto::types::data::{Ikm, Info};
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::{HkdfSalt, PrivateKeyIkmSalt};
use crate::io::ssh::backend::SignatureBackend;
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::model::wire::context;
use crate::support::kid::format_kid_half_display_lossy;
use crate::Result;
use tracing::debug;

const NON_DETERMINISTIC_SIGNATURE_MESSAGE: &str =
    "Non-deterministic signature detected: same input produced different signatures";

pub(super) struct PrivateKeyUseKey {
    pub(super) enc_key: XChaChaKey,
    pub(super) raw_sig: Ed25519RawSignature,
}

/// Build sign_message for SSH signature.
pub fn build_sign_message(ikm_salt_b64: &str) -> String {
    format!(
        "{}\n{}",
        context::SSHSIG_MESSAGE_PREFIX_PRIVATE_KEY_PROTECTION_V7,
        ikm_salt_b64
    )
}

/// Generate a random IKM salt for SSH-based key derivation.
pub fn generate_ikm_salt() -> Result<PrivateKeyIkmSalt> {
    Ok(PrivateKeyIkmSalt::new(fill_random_array::<32>()?))
}

/// Generate a random HKDF salt for SSH-based key derivation.
pub fn generate_hkdf_salt() -> Result<HkdfSalt> {
    Ok(HkdfSalt::new(fill_random_array::<32>()?))
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
    let raw_sig =
        sign_for_private_key_encryption(kid, backend, ssh_pubkey, message.as_bytes(), debug)?;
    derive_key_from_raw_signature(kid, &raw_sig, hkdf_salt, debug)
}

pub(super) fn derive_key_for_private_key_use(
    kid: &str,
    ikm_salt_b64: &str,
    hkdf_salt: &HkdfSalt,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    debug: bool,
) -> Result<PrivateKeyUseKey> {
    let message = build_sign_message(ikm_salt_b64);
    let raw_sig = sign_for_private_key_use(kid, backend, ssh_pubkey, message.as_bytes(), debug)?;
    let enc_key = derive_key_from_raw_signature(kid, &raw_sig, hkdf_salt, debug)?;
    Ok(PrivateKeyUseKey { enc_key, raw_sig })
}

pub(super) fn enforce_private_key_use_signature_determinism(
    kid: &str,
    ikm_salt_b64: &str,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    expected_raw_sig: &Ed25519RawSignature,
    debug: bool,
) -> Result<()> {
    let message = build_sign_message(ikm_salt_b64);
    if debug {
        debug!(
            "[CRYPTO] SSH: sign_sshsig retry diagnosis (kid: {})",
            format_kid_half_display_lossy(kid)
        );
    }
    let retry_sig = backend.sign_sshsig(
        ssh::KEY_PROTECTION_NAMESPACE,
        ssh_pubkey,
        message.as_bytes(),
    )?;
    if retry_sig != *expected_raw_sig {
        return Err(non_deterministic_signature_error());
    }
    Ok(())
}

fn sign_for_private_key_encryption(
    kid: &str,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    message: &[u8],
    debug: bool,
) -> Result<Ed25519RawSignature> {
    if debug {
        debug!(
            "[CRYPTO] SSH: sign_sshsig x2 determinism check (kid: {})",
            format_kid_half_display_lossy(kid)
        );
    }
    backend
        .sign_sshsig_deterministic(ssh::KEY_PROTECTION_NAMESPACE, ssh_pubkey, message)
        .map_err(build_determinism_error)
}

fn sign_for_private_key_use(
    kid: &str,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    message: &[u8],
    debug: bool,
) -> Result<Ed25519RawSignature> {
    if debug {
        debug!(
            "[CRYPTO] SSH: sign_sshsig (kid: {})",
            format_kid_half_display_lossy(kid)
        );
    }
    backend.sign_sshsig(ssh::KEY_PROTECTION_NAMESPACE, ssh_pubkey, message)
}

fn derive_key_from_raw_signature(
    kid: &str,
    raw_sig: &Ed25519RawSignature,
    hkdf_salt: &HkdfSalt,
    debug: bool,
) -> Result<XChaChaKey> {
    if debug {
        debug!(
            "[CRYPTO] HKDF-SHA256: private key enc key derivation (kid: {})",
            format_kid_half_display_lossy(kid)
        );
    }
    let ikm = Ikm::from(&raw_sig.as_bytes()[..]);
    let info = Info::from_string(&format!(
        "{}:{}",
        context::HKDF_INFO_PRIVATE_KEY_SSHSIG_V7,
        kid
    ));
    let cek = kdf::expand_to_array(&ikm, Some(hkdf_salt), &info)?;
    XChaChaKey::from_slice(cek.as_bytes())
}

fn non_deterministic_signature_error() -> crate::Error {
    crate::Error::Crypto {
        message: "W_SSH_NONDETERMINISTIC: SSH signature is non-deterministic".into(),
        source: None,
    }
}

fn build_determinism_error(error: crate::Error) -> crate::Error {
    if error
        .to_string()
        .contains(NON_DETERMINISTIC_SIGNATURE_MESSAGE)
    {
        return non_deterministic_signature_error();
    }

    error
}
