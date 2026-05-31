// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::BufferedCryptoRng;
use rand::RngCore;
use zeroize::Zeroizing;

#[test]
fn test_buffered_crypto_rng_supplies_exact_bytes() {
    let seed = Zeroizing::new([7u8; 32]);
    let mut rng = BufferedCryptoRng::new(seed);
    let mut output = [0u8; 32];

    rng.fill_bytes(&mut output);

    assert_eq!(output, [7u8; 32]);
    rng.ensure_consumed_exactly().unwrap();
}

#[test]
fn test_buffered_crypto_rng_rejects_partial_consumption() {
    let seed = Zeroizing::new([7u8; 32]);
    let mut rng = BufferedCryptoRng::new(seed);
    let mut output = [0u8; 16];

    rng.fill_bytes(&mut output);

    let err = rng.ensure_consumed_exactly().unwrap_err();
    assert_eq!(
        err.to_string(),
        "Cryptographic error: HPKE sender RNG consumed unexpected randomness"
    );
}

#[test]
fn test_buffered_crypto_rng_rejects_extra_consumption() {
    let seed = Zeroizing::new([7u8; 32]);
    let mut rng = BufferedCryptoRng::new(seed);
    let mut output = [0u8; 33];

    rng.fill_bytes(&mut output);

    assert_eq!(output, [0u8; 33]);
    let err = rng.ensure_consumed_exactly().unwrap_err();
    assert_eq!(
        err.to_string(),
        "Cryptographic error: HPKE sender RNG consumed unexpected randomness"
    );
}

#[test]
fn test_buffered_crypto_rng_rejects_integer_generation() {
    let seed = Zeroizing::new([7u8; 32]);
    let mut rng = BufferedCryptoRng::new(seed);

    assert_eq!(rng.next_u32(), 0);

    let err = rng.ensure_consumed_exactly().unwrap_err();
    assert_eq!(
        err.to_string(),
        "Cryptographic error: HPKE sender RNG consumed unexpected randomness"
    );
}
