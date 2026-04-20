// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! PublicKey v3 model
//!
//! Includes attested identity and verified public key types for functional domain modeling.

use crate::model::identifiers::format::PUBLIC_KEY_V4;
use serde::{Deserialize, Serialize};

pub use super::public_key_verified::{
    AttestationProof, AttestedIdentity, VerifiedBindingClaims, VerifiedPublicKey,
    VerifiedPublicKeyAttested, VerifiedRecipientKey,
};

/// PublicKey v4 document (signed container)
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
    /// Format identifier: "secretenv.public.key@4"
    pub format: String,

    /// Member handle serialized with the on-wire field name `member_id`
    pub member_id: String,

    /// Statement ID (canonical Crockford Base32, 32 characters)
    pub kid: String,

    /// Identity (Keys + Attestation)
    pub identity: Identity,

    /// Optional binding claims (external service bindings; verified online)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_claims: Option<BindingClaims>,

    /// Expiration timestamp (RFC 3339)
    pub expires_at: String,

    /// Creation timestamp (RFC 3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Identity (Keys + Attestation)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub keys: IdentityKeys,
    pub attestation: Attestation,
}

/// Identity Keys (KEM + Sig)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityKeys {
    pub kem: JwkOkpPublicKey,
    pub sig: JwkOkpPublicKey,
}

/// JWK/OKP public key (RFC 7517 / RFC 8037).
///
/// SecretEnv v3 uses:
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
    /// Method: "ssh"
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

    /// GitHub login (username). Required. Used for verification (REST GET /users/{login} and /keys).
    pub login: String,
}
impl PublicKey {
    /// Create a new PublicKey with the given parameters
    pub fn new(
        member_id: String,
        kid: String,
        identity: Identity,
        binding_claims: Option<BindingClaims>,
        expires_at: String,
        created_at: Option<String>,
        signature: String,
    ) -> Self {
        let protected = PublicKeyProtected {
            format: PUBLIC_KEY_V4.to_string(),
            member_id,
            kid,
            identity,
            binding_claims,
            expires_at,
            created_at,
        };
        Self {
            protected,
            signature,
        }
    }
}
