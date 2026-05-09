// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Password-based key derivation for PrivateKey protection (Argon2id + HKDF-SHA256)

use crate::crypto::kdf;
use crate::crypto::rng::fill_random_array;
use crate::crypto::types::data::{Ikm, Info};
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::{HkdfSalt, PrivateKeyIkmSalt};
use crate::model::wire::context;
use crate::support::kid::format_kid_display_lossy;
use crate::support::secret::SecretString;
use crate::Result;
use argon2::Argon2;
use tracing::debug;
use zeroize::Zeroizing;

// RFC 9106 Section 4 "second recommended" option for Argon2id:
// m=64 MiB, t=3, p=4
const ARGON2_MEMORY_COST_KIB: u32 = 65536;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Generate a random salt for Argon2id input.
pub fn generate_ikm_salt() -> Result<PrivateKeyIkmSalt> {
    Ok(PrivateKeyIkmSalt::new(fill_random_array::<32>()?))
}

/// Generate a random salt for HKDF-Extract.
pub fn generate_hkdf_salt() -> Result<HkdfSalt> {
    Ok(HkdfSalt::new(fill_random_array::<32>()?))
}

/// Derive an encryption key from a password using Argon2id + HKDF-SHA256
///
/// Pipeline:
/// 1. Password + salt -> Argon2id -> 32-byte IKM
/// 2. IKM + salt -> HKDF-SHA256 (with kid-bound info) -> XChaChaKey
pub fn derive_key_from_password(
    password: &SecretString,
    ikm_salt: &PrivateKeyIkmSalt,
    hkdf_salt: &HkdfSalt,
    kid: &str,
    debug_enabled: bool,
) -> Result<XChaChaKey> {
    if debug_enabled {
        debug!(
            "[CRYPTO] Argon2id: password hash (kid: {}, m: {}, t: {}, p: {})",
            format_kid_display_lossy(kid),
            ARGON2_MEMORY_COST_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM
        );
    }
    let ikm = argon2id_hash(password, ikm_salt)?;

    if debug_enabled {
        debug!(
            "[CRYPTO] HKDF-SHA256: password key derivation (kid: {})",
            format_kid_display_lossy(kid)
        );
    }
    let info = Info::from_string(&format!(
        "{}:{}",
        context::PASSWORD_PRIVATE_KEY_ENC_INFO_PREFIX_V6,
        kid
    ));
    let cek = kdf::expand_to_array(&Ikm::from(ikm.as_ref()), Some(hkdf_salt), &info)?;
    XChaChaKey::from_slice(cek.as_bytes())
}

/// Hash password with Argon2id, returning a 32-byte IKM wrapped in Zeroizing
fn argon2id_hash(password: &SecretString, salt: &PrivateKeyIkmSalt) -> Result<Zeroizing<[u8; 32]>> {
    let argon2_params = fixed_argon2_params()?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(
            password.as_str().as_bytes(),
            salt.as_bytes(),
            output.as_mut(),
        )
        .map_err(|e| crate::Error::Crypto {
            message: format!("Argon2id hashing failed: {}", e),
            source: None,
        })?;

    Ok(output)
}

fn fixed_argon2_params() -> Result<argon2::Params> {
    argon2::Params::new(
        ARGON2_MEMORY_COST_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| crate::Error::Crypto {
        message: format!("Invalid fixed Argon2id parameters: {}", e),
        source: None,
    })
}
