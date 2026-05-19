// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact signature and key-possession proof model.
//!
//! Unified signature format used by file-enc and kv-enc artifacts.
//!
//! # Security
//!
//! The signature format does not include msg_hash field for security reasons:
//! verifiers must compute the hash themselves rather than trusting
//! a provided hash value.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::model::public_key::PublicKey;
use crate::support::codec::base64_public::{decode_base64url_nopad, encode_base64url_nopad};

pub const KEY_POSSESSION_HMAC_SHA256: &str = "hmac-sha256";
pub const KEY_POSSESSION_HMAC_SHA256_TAG_LEN: usize = 32;

/// Supported key-possession proof algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPossessionProofAlgorithm {
    HmacSha256,
}

impl KeyPossessionProofAlgorithm {
    pub fn parse(prefix: &str) -> Result<Self, KeyPossessionProofError> {
        match prefix {
            KEY_POSSESSION_HMAC_SHA256 => Ok(Self::HmacSha256),
            other => Err(KeyPossessionProofError::UnsupportedAlgorithm(
                other.to_string(),
            )),
        }
    }

    pub fn as_wire_prefix(self) -> &'static str {
        match self {
            Self::HmacSha256 => KEY_POSSESSION_HMAC_SHA256,
        }
    }

    pub fn tag_len(self) -> usize {
        match self {
            Self::HmacSha256 => KEY_POSSESSION_HMAC_SHA256_TAG_LEN,
        }
    }
}

/// Validation error for a key-possession proof string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPossessionProofError {
    InvalidFormat,
    UnsupportedAlgorithm(String),
    InvalidBase64,
    InvalidTagLength { expected: usize, actual: usize },
}

impl fmt::Display for KeyPossessionProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(formatter, "Invalid key-possession proof format"),
            Self::UnsupportedAlgorithm(alg) => {
                write!(
                    formatter,
                    "Unsupported key-possession proof algorithm: {alg}"
                )
            }
            Self::InvalidBase64 => write!(formatter, "Invalid key-possession proof Base64"),
            Self::InvalidTagLength { expected, actual } => write!(
                formatter,
                "Invalid key-possession proof tag length: expected {expected} bytes, got {actual}"
            ),
        }
    }
}

impl std::error::Error for KeyPossessionProofError {}

/// HMAC-backed proof that a signer possessed the artifact content key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPossessionProof {
    wire: String,
    algorithm: KeyPossessionProofAlgorithm,
    tag: Vec<u8>,
}

impl KeyPossessionProof {
    pub fn try_new(
        algorithm: KeyPossessionProofAlgorithm,
        tag: &[u8],
    ) -> Result<Self, KeyPossessionProofError> {
        validate_tag_len(algorithm, tag.len())?;
        let wire = format!(
            "{}:{}",
            algorithm.as_wire_prefix(),
            encode_base64url_nopad(tag)
        );
        Ok(Self {
            wire,
            algorithm,
            tag: tag.to_vec(),
        })
    }

    pub fn parse(wire: &str) -> Result<Self, KeyPossessionProofError> {
        let (prefix, tag_b64) = wire
            .split_once(':')
            .ok_or(KeyPossessionProofError::InvalidFormat)?;
        if prefix.is_empty() || tag_b64.is_empty() || tag_b64.contains(':') {
            return Err(KeyPossessionProofError::InvalidFormat);
        }
        let algorithm = KeyPossessionProofAlgorithm::parse(prefix)?;
        let tag = decode_base64url_nopad(tag_b64, "key-possession proof")
            .map_err(|_| KeyPossessionProofError::InvalidBase64)?;
        validate_tag_len(algorithm, tag.len())?;
        Ok(Self {
            wire: wire.to_string(),
            algorithm,
            tag,
        })
    }

    pub fn algorithm(&self) -> KeyPossessionProofAlgorithm {
        self.algorithm
    }

    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    pub fn as_str(&self) -> &str {
        &self.wire
    }
}

fn validate_tag_len(
    algorithm: KeyPossessionProofAlgorithm,
    actual: usize,
) -> Result<(), KeyPossessionProofError> {
    let expected = algorithm.tag_len();
    if actual == expected {
        Ok(())
    } else {
        Err(KeyPossessionProofError::InvalidTagLength { expected, actual })
    }
}

impl Serialize for KeyPossessionProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.wire)
    }
}

struct KeyPossessionProofVisitor;

impl Visitor<'_> for KeyPossessionProofVisitor {
    type Value = KeyPossessionProof;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a key-possession proof string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        KeyPossessionProof::parse(value).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for KeyPossessionProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(KeyPossessionProofVisitor)
    }
}

/// Artifact signature structure
///
/// Used by both file-enc `signature` field and kv-enc `SIG` line.
/// Simplified format without msg_hash or version fields.
///
/// # Format
///
/// - `alg`: Signature algorithm, always "eddsa-ed25519"
/// - `kid`: signer key statement ID in canonical Crockford Base32 form
/// - `signer_pub`: Required PublicKey document for self-contained verification
/// - `mac`: Key-possession proof over the artifact body bytes
/// - `sig`: Ed25519 signature in base64url encoding (no padding)
///
/// # Example JSON
///
/// ```json
/// {
///   "alg": "eddsa-ed25519",
///   "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
///   "signer_pub": { /* PublicKey: secretenv:format:public-key@6 */ },
///   "mac": "hmac-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
///   "sig": "SGVsbG8gV29ybGQ..."
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSignature {
    /// Signature algorithm: "eddsa-ed25519"
    pub alg: String,

    /// Signer key statement ID in canonical Crockford Base32 form
    pub kid: String,

    /// Signer's PublicKey document required for self-contained verification
    pub signer_pub: PublicKey,

    /// Key-possession proof over the artifact body bytes
    pub mac: KeyPossessionProof,

    /// Signature bytes (base64url, no padding)
    pub sig: String,
}
