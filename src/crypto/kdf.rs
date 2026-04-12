// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key Derivation Functions

use crate::crypto::crypto_operation_failed;
use crate::crypto::types::data::{Ikm, Info};
use crate::crypto::types::keys::Cek;
use crate::crypto::types::primitives::AsHkdfSalt;
use crate::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Internal helper function for HKDF expansion
fn expand_internal(ikm: &Ikm, salt: Option<&[u8]>, info: &Info, output: &mut [u8]) -> Result<()> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm.as_bytes());
    hkdf.expand(info.as_bytes(), output)
        .map_err(|_| crypto_operation_failed("HKDF expand failed"))
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
pub fn expand<S: AsHkdfSalt>(
    ikm: &Ikm,
    salt: Option<&S>,
    info: &Info,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut okm = vec![0u8; length];
    let raw_salt = salt.map(|s| s.as_hkdf_salt_bytes());
    expand_internal(ikm, raw_salt, info, &mut okm)?;
    Ok(Zeroizing::new(okm))
}

/// Expand HKDF-SHA256 to fixed-size array
///
/// Only types implementing [`AsHkdfSalt`] can be passed as `salt`.
/// `PrivateKeyIkmSalt` does not implement this trait, preventing accidental misuse:
///
/// ```compile_fail
/// use secretenv::crypto::kdf::expand_to_array;
/// use secretenv::crypto::types::data::{Ikm, Info};
/// use secretenv::crypto::types::primitives::PrivateKeyIkmSalt;
/// let ikm = Ikm::from(&[0u8; 32][..]);
/// let salt = PrivateKeyIkmSalt::new([1u8; 32]);
/// let info = Info::from_string("test");
/// let _ = expand_to_array(&ikm, Some(&salt), &info);
/// ```
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt (None for empty salt)
/// * `info` - Context and application specific information
///
/// # Returns
/// Derived key material (32 bytes) as CEK
pub fn expand_to_array<S: AsHkdfSalt>(ikm: &Ikm, salt: Option<&S>, info: &Info) -> Result<Cek> {
    let mut okm = Zeroizing::new([0u8; 32]);
    let raw_salt = salt.map(|s| s.as_hkdf_salt_bytes());
    expand_internal(ikm, raw_salt, info, okm.as_mut())?;
    Ok(Cek::from_zeroizing(okm))
}
