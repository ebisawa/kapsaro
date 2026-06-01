// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic key types with type safety

use zeroize::Zeroizing;

macro_rules! define_zeroizing_key_type {
    ($(#[$meta:meta])* $name:ident, $type_name:literal) => {
        $(#[$meta])*
        pub struct $name(Zeroizing<[u8; 32]>);

        impl $name {
            /// Create a new key from 32 bytes.
            pub fn new(bytes: [u8; 32]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            /// Create a new key from zeroizing bytes without an extra copy.
            pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
                Self(bytes)
            }

            /// Get the key bytes.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl_fixed_size_type!($name, 32, $type_name, zeroizing);
    };
}

define_zeroizing_key_type!(
    /// XChaCha20-Poly1305 encryption key (32 bytes).
    ///
    /// This key is wrapped in Zeroizing for secure memory clearing.
    XChaChaKey,
    "XChaCha key"
);

define_zeroizing_key_type!(
    /// Master key for file-level encryption (32 bytes).
    ///
    /// This key is wrapped in Zeroizing for secure memory clearing.
    MasterKey,
    "master key"
);

define_zeroizing_key_type!(
    /// Content Encryption Key (32 bytes).
    ///
    /// This key is wrapped in Zeroizing for secure memory clearing.
    Cek,
    "CEK"
);

define_zeroizing_key_type!(
    /// HMAC key for artifact key-possession proofs (32 bytes).
    ///
    /// This key is derived from an artifact master key and is kept distinct from
    /// payload encryption keys at the type boundary.
    MacKey,
    "MAC key"
);
