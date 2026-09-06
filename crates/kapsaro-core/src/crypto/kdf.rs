// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! HKDF-SHA256 key derivation helpers.
//!
//! Provides one-shot derivation and reusable PRK expansion primitives.

use crate::crypto::build_crypto_operation_error;
use crate::crypto::types::data::{Ikm, Info};
use crate::crypto::types::primitives::AsHkdfSalt;
use crate::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// HKDF-SHA256 pseudorandom key for artifact key schedules.
///
/// This is the result of HKDF-Extract and is held so callers can derive
/// multiple purpose-specific keys via HKDF-Expand.
pub struct HkdfSha256Prk(Zeroizing<[u8; 32]>);

impl HkdfSha256Prk {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn expand_from_ikm(ikm: &Ikm, salt: Option<&[u8]>, info: &Info, output: &mut [u8]) -> Result<()> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm.as_bytes());
    expand_hkdf(&hkdf, info, output)
}

/// Run HKDF-Extract for an artifact key schedule.
///
/// Only types implementing [`AsHkdfSalt`] can be passed as `salt`, on the same
/// terms as [`derive_hkdf_sha256_array`].
pub fn derive_hkdf_sha256_prk<S: AsHkdfSalt>(ikm: &Ikm, salt: &S) -> HkdfSha256Prk {
    // The discarded second value is an HMAC context keyed with the PRK. The
    // SHA-256 cores it holds clear their state when dropped, which the sha2
    // `zeroize` feature provides; the padded key blocks the hmac crate builds
    // on its own stack are out of reach here.
    let (mut raw_prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_hkdf_salt_bytes()), ikm.as_bytes());
    let mut prk = Zeroizing::new([0u8; 32]);
    prk.as_mut().copy_from_slice(&raw_prk);
    // The output array type has no Zeroize impl of its own; clear it through
    // its slice view so the only surviving copy is the zeroizing one.
    raw_prk[..].zeroize();
    HkdfSha256Prk(prk)
}

/// Expand an artifact PRK to a 32-byte output.
pub fn derive_hkdf_sha256_array_from_prk(
    prk: &HkdfSha256Prk,
    info: &Info,
) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk.as_bytes())
        .map_err(|_| build_crypto_operation_error("HKDF PRK initialization failed"))?;
    let mut okm = Zeroizing::new([0u8; 32]);
    expand_hkdf(&hkdf, info, okm.as_mut())?;
    Ok(okm)
}

/// Expand HKDF-SHA256 to fixed-size array
///
/// Only types implementing [`AsHkdfSalt`] can be passed as `salt`, which keeps
/// salts meant for other key schedules out of HKDF-Extract.
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt (None for empty salt)
/// * `info` - Context and application specific information
///
/// # Returns
/// Derived key material (32 bytes)
pub fn derive_hkdf_sha256_array<S: AsHkdfSalt>(
    ikm: &Ikm,
    salt: Option<&S>,
    info: &Info,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut okm = Zeroizing::new([0u8; 32]);
    let raw_salt = salt.map(|s| s.as_hkdf_salt_bytes());
    expand_from_ikm(ikm, raw_salt, info, okm.as_mut())?;
    Ok(okm)
}

fn expand_hkdf(hkdf: &Hkdf<Sha256>, info: &Info, output: &mut [u8]) -> Result<()> {
    hkdf.expand(info.as_bytes(), output)
        .map_err(|_| build_crypto_operation_error("HKDF expand failed"))
}

#[cfg(test)]
#[path = "../../tests/unit/internal/crypto_kdf_internal_test.rs"]
mod crypto_kdf_internal_test;

#[cfg(test)]
#[path = "../../tests/unit/internal/crypto_kdf_test.rs"]
mod crypto_kdf_test;
