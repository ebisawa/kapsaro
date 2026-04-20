// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! PrivateKey v5 model.
//!
//! SSH Ed25519 encrypted private key storage for secretenv.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// PrivateKey v5 document (encrypted).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrivateKey {
    /// Protected header (used for AAD construction)
    pub protected: PrivateKeyProtected,

    /// Encrypted key material
    pub encrypted: EncryptedData,
}

/// Protected header (AAD source)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrivateKeyProtected {
    /// Format identifier: "secretenv.private.key@5"
    pub format: String,

    /// Member ID (ASCII identifier; allows .@_+-)
    pub member_id: String,

    /// Statement ID (canonical Crockford Base32, 32 characters)
    pub kid: String,

    /// Algorithm configuration
    pub alg: PrivateKeyAlgorithm,

    /// Creation timestamp (RFC 3339)
    pub created_at: String,

    /// Expiration timestamp (RFC 3339)
    pub expires_at: String,
}

/// Algorithm configuration (tagged by KDF method)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kdf")]
#[serde(deny_unknown_fields)]
pub enum PrivateKeyAlgorithm {
    /// SSH-signature-based key derivation
    #[serde(rename = "sshsig-ed25519-hkdf-sha256")]
    SshSig {
        fpr: String,
        ikm_salt: String,
        hkdf_salt: String,
        aead: String,
    },
    /// Argon2id password-based key derivation
    #[serde(rename = "argon2id-m64t3p4-hkdf-sha256")]
    Argon2id {
        ikm_salt: String,
        hkdf_salt: String,
        aead: String,
    },
}

impl PrivateKeyAlgorithm {
    /// IKM salt value.
    pub fn ikm_salt(&self) -> &str {
        match self {
            Self::SshSig { ikm_salt, .. } | Self::Argon2id { ikm_salt, .. } => ikm_salt,
        }
    }

    /// HKDF salt value.
    pub fn hkdf_salt(&self) -> &str {
        match self {
            Self::SshSig { hkdf_salt, .. } | Self::Argon2id { hkdf_salt, .. } => hkdf_salt,
        }
    }

    /// AEAD algorithm identifier (common to all variants)
    pub fn aead(&self) -> &str {
        match self {
            Self::SshSig { aead, .. } | Self::Argon2id { aead, .. } => aead,
        }
    }
}

/// Encrypted key material
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedData {
    /// Nonce (base64url, 24 bytes)
    pub nonce: String,

    /// Ciphertext (base64url)
    pub ct: String,
}

/// Plaintext key material (inside encrypted.ct).
#[derive(Serialize, Deserialize, PartialEq, Zeroize)]
#[zeroize(drop)]
#[serde(deny_unknown_fields)]
pub struct PrivateKeyPlaintext {
    /// Keys (KEM + Sig key pairs)
    pub keys: IdentityKeysPrivate,
}

/// Identity Keys Private (KEM + Sig with private components)
#[derive(Serialize, Deserialize, PartialEq, Zeroize)]
#[zeroize(drop)]
#[serde(deny_unknown_fields)]
pub struct IdentityKeysPrivate {
    /// KEM key pair (X25519).
    pub kem: JwkOkpPrivateKey,
    /// Sig key pair (Ed25519).
    pub sig: JwkOkpPrivateKey,
}

/// JWK/OKP private key (RFC 7517 / RFC 8037).
///
/// SecretEnv v3 plaintext key material uses:
/// - `crv = "X25519"` for KEM
/// - `crv = "Ed25519"` for signatures
///
/// It also includes public component `x` for PublicKey reconstruction.
#[derive(Serialize, Deserialize, PartialEq, Zeroize)]
#[zeroize(drop)]
#[serde(deny_unknown_fields)]
pub struct JwkOkpPrivateKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub d: String,
}

impl std::fmt::Debug for JwkOkpPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwkOkpPrivateKey")
            .field("kty", &self.kty)
            .field("crv", &self.crv)
            .field("x", &self.x)
            .field("d", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for PrivateKeyPlaintext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKeyPlaintext")
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for IdentityKeysPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeysPrivate")
            .field("kem", &"[REDACTED]")
            .field("sig", &"[REDACTED]")
            .finish()
    }
}

impl PrivateKey {
    /// Create a new PrivateKey with the given parameters
    pub fn new(protected: PrivateKeyProtected, encrypted: EncryptedData) -> Self {
        Self {
            protected,
            encrypted,
        }
    }
}
