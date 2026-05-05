// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Secure random byte helpers.

use crate::crypto::build_crypto_operation_error;
use crate::Result;
use rand::RngCore;
use rand::{rngs::OsRng, CryptoRng, TryRngCore};
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

pub(crate) fn hpke_sender_setup_rng() -> Result<BufferedCryptoRng<32>> {
    Ok(BufferedCryptoRng::new(fill_secret_array::<32>()?))
}

pub(crate) struct BufferedCryptoRng<const N: usize> {
    bytes: Zeroizing<[u8; N]>,
    position: usize,
    invalid_consumption: bool,
}

impl<const N: usize> BufferedCryptoRng<N> {
    fn new(bytes: Zeroizing<[u8; N]>) -> Self {
        Self {
            bytes,
            position: 0,
            invalid_consumption: false,
        }
    }

    pub(crate) fn ensure_consumed_exactly(self) -> Result<()> {
        if self.invalid_consumption || self.position != N {
            return Err(build_crypto_operation_error(
                "HPKE sender RNG consumed unexpected randomness",
            ));
        }
        Ok(())
    }

    fn remaining(&self) -> usize {
        N.saturating_sub(self.position)
    }

    fn mark_invalid(&mut self) {
        self.invalid_consumption = true;
    }
}

impl<const N: usize> RngCore for BufferedCryptoRng<N> {
    fn next_u32(&mut self) -> u32 {
        self.mark_invalid();
        0
    }

    fn next_u64(&mut self) -> u64 {
        self.mark_invalid();
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if dest.len() > self.remaining() {
            self.mark_invalid();
            dest.fill(0);
            return;
        }

        let end = self.position + dest.len();
        dest.copy_from_slice(&self.bytes[self.position..end]);
        self.position = end;
    }
}

impl<const N: usize> CryptoRng for BufferedCryptoRng<N> {}

#[cfg(test)]
#[path = "../../tests/unit/internal/crypto_rng_internal_test.rs"]
mod tests;
