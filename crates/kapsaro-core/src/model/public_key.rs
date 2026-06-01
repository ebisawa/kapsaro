// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! PublicKey model.
//!
//! Captures the signed public key statement and attestation metadata.

use crate::model::wire::format::PUBLIC_KEY_V1;
use serde::{Deserialize, Serialize};

pub use super::public_key_verified::{
    AttestationProof, AttestedKeyStatement, VerifiedBindingClaims, VerifiedPublicKeyAttested,
    VerifiedRecipientKey, VerifiedSigningPublicKey,
};

/// PublicKey v7 document (signed container)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    /// The protected content of the public key (signed payload)
    pub protected: PublicKeyProtected,

    /// Ed25519 self-signature over the protected content
    pub signature: String,
}

/// The protected content of the public key (Signed payload)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyProtected {
    /// Format identifier: "kapsaro:format:public-key@1"
    pub format: String,

    /// Subject handle asserted by this key statement.
    pub subject_handle: String,

    /// Statement ID (canonical Crockford Base32, 32 characters)
    pub kid: String,

    /// Kapsaro public key material.
    pub keys: IdentityKeys,

    /// Optional binding claims (external service bindings; verified online)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_claims: Option<BindingClaims>,

    /// SSH attestation over the public key statement body.
    pub attestation: Attestation,

    /// Expiration timestamp (RFC 3339)
    pub expires_at: String,

    /// Creation timestamp (RFC 3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Construction input for a PublicKey document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyParts {
    pub subject_handle: String,
    pub kid: String,
    pub keys: IdentityKeys,
    pub binding_claims: Option<BindingClaims>,
    pub attestation: Attestation,
    pub expires_at: String,
    pub created_at: Option<String>,
    pub signature: String,
}

/// Kapsaro public keys (KEM + signature).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityKeys {
    pub kem: JwkOkpPublicKey,
    pub sig: JwkOkpPublicKey,
}

/// JWK/OKP public key (RFC 7517 / RFC 8037).
///
/// Kapsaro v3 uses:
/// - `crv = "X25519"` for KEM
/// - `crv = "Ed25519"` for signatures
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JwkOkpPublicKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

/// SSH attestation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    /// Method: "ssh-sign"
    pub method: String,

    /// SSH public key (OpenSSH format)
    #[serde(rename = "pub")]
    pub pub_: String,

    /// Signature (base64url)
    pub sig: String,
}

/// Claims about external service bindings (e.g. GitHub). Verified online.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingClaims {
    /// GitHub account binding (claim; verified by member verify)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_account: Option<GithubAccount>,
}

/// GitHub account binding (optional at document level; when present, both id and login are required)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GithubAccount {
    /// GitHub user ID (numeric, stable across login changes)
    pub id: u64,

    /// GitHub login (username). Required by the document schema; online verification starts from id.
    pub login: String,
}
impl PublicKey {
    /// Create a new PublicKey with the given parameters
    pub fn new(parts: PublicKeyParts) -> Self {
        let protected = PublicKeyProtected {
            format: PUBLIC_KEY_V1.to_string(),
            subject_handle: parts.subject_handle,
            kid: parts.kid,
            keys: parts.keys,
            binding_claims: parts.binding_claims,
            attestation: parts.attestation,
            expires_at: parts.expires_at,
            created_at: parts.created_at,
        };
        Self {
            protected,
            signature: parts.signature,
        }
    }
}
