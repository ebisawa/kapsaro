// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Secure random byte helpers.

use crate::crypto::build_crypto_operation_error;
use crate::Result;
use rand::{rngs::OsRng, TryRngCore};
use zeroize::Zeroizing;

const OS_RNG_ERROR_MESSAGE: &str = "OS random number generation failed";

/// Fill a buffer with cryptographically secure random bytes from the OS.
pub(crate) fn fill_random_bytes(bytes: &mut [u8]) -> Result<()> {
    let mut rng = OsRng;
    rng.try_fill_bytes(bytes)
        .map_err(|_| build_crypto_operation_error(OS_RNG_ERROR_MESSAGE))
}

/// Generate a fixed-size random byte array.
pub(crate) fn fill_random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    fill_random_bytes(&mut bytes)?;
    Ok(bytes)
}

/// Generate a fixed-size random byte array wrapped in `Zeroizing`.
pub(crate) fn fill_secret_array<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0u8; N]);
    fill_random_bytes(bytes.as_mut())?;
    Ok(bytes)
}
