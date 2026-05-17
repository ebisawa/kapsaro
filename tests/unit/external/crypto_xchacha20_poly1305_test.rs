// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! XChaCha20-Poly1305 AEAD tests

use secretenv_core::cli_api::test_support::primitives::aead::xchacha::{
    decrypt, encrypt, NONCE_SIZE,
};
use secretenv_core::cli_api::test_support::primitives::types::data::{Aad, Plaintext};
use secretenv_core::cli_api::test_support::primitives::types::keys::XChaChaKey;
use secretenv_core::cli_api::test_support::primitives::types::primitives::XChaChaNonce;

#[test]
fn test_xchacha20_encrypt_decrypt_roundtrip() {
    let key = XChaChaKey::new([0x42u8; 32]);
    let nonce = XChaChaNonce::new([0x01u8; NONCE_SIZE]);
    let aad = Aad::from(b"secretenv:context:aad:kv-enc:entry-payload@6|kid|key" as &[u8]);
    let plaintext = Plaintext::from(b"DATABASE_URL=postgresql://localhost/db" as &[u8]);

    let ciphertext = encrypt(&key, &nonce, &aad, &plaintext).expect("encrypt should succeed");
    assert!(
        ciphertext.as_bytes().len() > plaintext.as_bytes().len(),
        "ciphertext should include tag"
    );

    let decrypted = decrypt(&key, &nonce, &aad, &ciphertext).expect("decrypt should succeed");
    assert_eq!(
        decrypted.as_bytes(),
        plaintext.as_bytes(),
        "roundtrip should preserve plaintext"
    );
}

#[test]
fn test_xchacha20_nonce_24_bytes() {
    // XChaCha20-Poly1305 requires 24-byte nonce
    assert_eq!(NONCE_SIZE, 24, "XChaCha20-Poly1305 nonce must be 24 bytes");
}

#[test]
fn test_xchacha20_wrong_nonce_error() {
    use secretenv_core::cli_api::test_support::primitives::types::data::{Aad, Plaintext};

    let key = XChaChaKey::new([0x42u8; 32]);
    let nonce = XChaChaNonce::new([0x01u8; NONCE_SIZE]);
    let wrong_nonce = XChaChaNonce::new([0xFFu8; NONCE_SIZE]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret data" as &[u8]);

    let ciphertext = encrypt(&key, &nonce, &aad, &plaintext).expect("encrypt should succeed");

    let result = decrypt(&key, &wrong_nonce, &aad, &ciphertext);
    assert!(result.is_err(), "decrypt with wrong nonce should fail");
}

#[test]
fn test_xchacha20_tampered_ciphertext_error() {
    use secretenv_core::cli_api::test_support::primitives::types::data::{
        Aad, Ciphertext, Plaintext,
    };

    let key = XChaChaKey::new([0x42u8; 32]);
    let nonce = XChaChaNonce::new([0x01u8; NONCE_SIZE]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret data" as &[u8]);

    let mut ciphertext_bytes = encrypt(&key, &nonce, &aad, &plaintext)
        .expect("encrypt should succeed")
        .into_bytes();

    // Tamper with ciphertext
    if !ciphertext_bytes.is_empty() {
        ciphertext_bytes[0] ^= 0xFF;
    }
    let ciphertext = Ciphertext::from(ciphertext_bytes);

    let result = decrypt(&key, &nonce, &aad, &ciphertext);
    assert!(
        result.is_err(),
        "decrypt with tampered ciphertext should fail"
    );
}

#[test]
fn test_xchacha20_aad_mismatch_error() {
    use secretenv_core::cli_api::test_support::primitives::types::data::{Aad, Plaintext};

    let key = XChaChaKey::new([0x42u8; 32]);
    let nonce = XChaChaNonce::new([0x01u8; NONCE_SIZE]);
    let aad = Aad::from(b"correct-aad" as &[u8]);
    let wrong_aad = Aad::from(b"wrong-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret data" as &[u8]);

    let ciphertext = encrypt(&key, &nonce, &aad, &plaintext).expect("encrypt should succeed");

    let result = decrypt(&key, &nonce, &wrong_aad, &ciphertext);
    assert!(result.is_err(), "decrypt with wrong AAD should fail");
}

#[test]
fn test_xchacha20_wrong_key_error_message_sanitized() {
    let key = XChaChaKey::new([0x42u8; 32]);
    let wrong_key = XChaChaKey::new([0x99u8; 32]);
    let nonce = XChaChaNonce::new([0x01u8; NONCE_SIZE]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret data" as &[u8]);

    let ciphertext = encrypt(&key, &nonce, &aad, &plaintext).expect("encrypt should succeed");
    let err = decrypt(&wrong_key, &nonce, &aad, &ciphertext).unwrap_err();

    assert_eq!(
        err.to_string(),
        "Cryptographic error: XChaCha20-Poly1305 decryption failed"
    );
}

#[test]
fn test_xchacha20_empty_plaintext() {
    use secretenv_core::cli_api::test_support::primitives::types::data::{Aad, Plaintext};

    let key = XChaChaKey::new([0x42u8; 32]);
    let nonce = XChaChaNonce::new([0x01u8; NONCE_SIZE]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"" as &[u8]);

    let ciphertext =
        encrypt(&key, &nonce, &aad, &plaintext).expect("encrypt empty plaintext should succeed");
    let decrypted =
        decrypt(&key, &nonce, &aad, &ciphertext).expect("decrypt empty plaintext should succeed");
    assert_eq!(decrypted.as_bytes(), plaintext.as_bytes());
}
