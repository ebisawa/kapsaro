// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Known-answer tests for the HPKE suite against RFC 9180 Appendix A.2.
//! Pins interoperability of DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305.

use super::{derive_public_key_from_secret, open_base, X25519PublicKey, X25519SecretKey};
use crate::crypto::types::data::{Aad, Ciphertext, Enc, Info, Plaintext};

// RFC 9180 A.2, Base mode setup information.
const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
const SK_RM: &str = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb";
const PK_RM: &str = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a";
const ENC: &str = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a";

// RFC 9180 A.2, Encryption 0.
const PLAINTEXT: &str = "4265617574792069732074727574682c20747275746820626561757479";
const AAD: &str = "436f756e742d30";
const CIPHERTEXT: &str = concat!(
    "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c",
    "8b60b4db21993c62ce81883d2dd1b51a28",
);

fn hex_array(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

/// The sender side draws an ephemeral key from the OS, so its output cannot be
/// pinned. The receiver side takes every input as an argument and covers the
/// same key schedule.
#[test]
fn test_open_base_matches_the_rfc9180_a2_vector() {
    let plaintext = open_base(
        &X25519SecretKey::from_bytes(hex_array(SK_RM)),
        &Enc::from(hex::decode(ENC).unwrap()),
        &Info::from(hex::decode(INFO).unwrap()),
        &Aad::from(hex::decode(AAD).unwrap()),
        &Ciphertext::from(hex::decode(CIPHERTEXT).unwrap()),
    )
    .unwrap();

    assert_eq!(
        hex::encode(Plaintext::as_bytes(&plaintext)),
        PLAINTEXT,
        "decrypted plaintext must match the published vector",
    );
}

#[test]
fn test_derive_public_key_matches_the_rfc9180_a2_vector() {
    let public_key =
        derive_public_key_from_secret(&X25519SecretKey::from_bytes(hex_array(SK_RM))).unwrap();

    assert_eq!(
        hex::encode(X25519PublicKey::as_bytes(&public_key)),
        PK_RM,
        "derived recipient public key must match the published vector",
    );
}

/// The AAD is authenticated, so a change to it has to make the open fail rather
/// than yield different plaintext.
#[test]
fn test_open_base_rejects_a_modified_aad() {
    let result = open_base(
        &X25519SecretKey::from_bytes(hex_array(SK_RM)),
        &Enc::from(hex::decode(ENC).unwrap()),
        &Info::from(hex::decode(INFO).unwrap()),
        &Aad::from(hex::decode("436f756e742d31").unwrap()),
        &Ciphertext::from(hex::decode(CIPHERTEXT).unwrap()),
    );

    assert!(result.is_err());
}
