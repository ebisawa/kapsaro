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
use zeroize::Zeroizing;

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
pub fn derive_hkdf_sha256_prk(ikm: &Ikm, salt: &[u8]) -> HkdfSha256Prk {
    let (raw_prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm.as_bytes());
    let mut prk = Zeroizing::new([0u8; 32]);
    prk.as_mut().copy_from_slice(&raw_prk);
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

/// Expand HKDF-SHA256
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt (None for empty salt)
/// * `info` - Context and application specific information
/// * `length` - Output length in bytes
///
/// # Returns
/// Derived key material
pub fn derive_hkdf_sha256_bytes<S: AsHkdfSalt>(
    ikm: &Ikm,
    salt: Option<&S>,
    info: &Info,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut okm = vec![0u8; length];
    let raw_salt = salt.map(|s| s.as_hkdf_salt_bytes());
    expand_from_ikm(ikm, raw_salt, info, &mut okm)?;
    Ok(Zeroizing::new(okm))
}

/// Expand HKDF-SHA256 to fixed-size array
///
/// Only types implementing [`AsHkdfSalt`] can be passed as `salt`.
/// `PrivateKeyIkmSalt` does not implement this trait, preventing accidental misuse:
///
/// ```compile_fail
/// use secretenv_core::crypto::kdf::derive_hkdf_sha256_array;
/// use secretenv_core::crypto::types::data::{Ikm, Info};
/// use secretenv_core::crypto::types::primitives::PrivateKeyIkmSalt;
/// let ikm = Ikm::from(&[0u8; 32][..]);
/// let salt = PrivateKeyIkmSalt::new([1u8; 32]);
/// let info = Info::from_string("test");
/// let _ = derive_hkdf_sha256_array(&ikm, Some(&salt), &info);
/// ```
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
mod tests;
