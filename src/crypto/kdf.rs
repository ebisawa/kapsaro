// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key Derivation Functions

use crate::crypto::crypto_operation_failed;
use crate::crypto::types::data::{Ikm, Info};
use crate::crypto::types::keys::Cek;
use crate::crypto::types::primitives::Salt;
use crate::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Internal helper function for HKDF expansion
fn expand_internal(ikm: &Ikm, salt: Option<&Salt>, info: &Info, output: &mut [u8]) -> Result<()> {
    let hkdf = Hkdf::<Sha256>::new(salt.map(|s| s.as_bytes() as &[u8]), ikm.as_bytes());
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
pub fn expand(
    ikm: &Ikm,
    salt: Option<&Salt>,
    info: &Info,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut okm = vec![0u8; length];
    expand_internal(ikm, salt, info, &mut okm)?;
    Ok(Zeroizing::new(okm))
}

/// Expand HKDF-SHA256 to fixed-size array
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt (None for empty salt)
/// * `info` - Context and application specific information
///
/// # Returns
/// Derived key material (32 bytes) as CEK
pub fn expand_to_array(ikm: &Ikm, salt: Option<&Salt>, info: &Info) -> Result<Cek> {
    let mut okm = Zeroizing::new([0u8; 32]);
    expand_internal(ikm, salt, info, okm.as_mut())?;
    Ok(Cek::from_zeroizing(okm))
}
