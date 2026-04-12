// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local Trust Store document model
//!
//! Format: secretenv.trust.local@2
//! A signed JSON container holding TOFU approval cache (known_keys).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Local Trust Store top-level structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustStoreDocument {
    /// Protected content (signature target)
    pub protected: TrustStoreProtected,
    /// Signature over protected object
    pub signature: TrustStoreSignature,
}

/// Trust Store signature structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustStoreSignature {
    /// Signature algorithm: "eddsa-ed25519"
    pub alg: String,

    /// Signer key statement ID in canonical Crockford Base32 form
    pub kid: String,

    /// Signature bytes (base64url, no padding)
    pub sig: String,
}

/// Trust Store protected object (signature target)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustStoreProtected {
    /// Format identifier: "secretenv.trust.local@2"
    pub format: String,

    /// Owner member ID for this local trust store
    pub owner_member_id: String,

    /// Creation timestamp (RFC 3339 UTC, trailing 'Z')
    pub created_at: String,

    /// Last update timestamp (RFC 3339 UTC, trailing 'Z')
    pub updated_at: String,

    /// Approved key records
    pub known_keys: Vec<KnownKey>,
}

/// A single approved key record in the TOFU cache.
///
/// Does NOT use `deny_unknown_fields` to allow forward-compatible
/// extension with future metadata fields (spec §9.4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnownKey {
    /// Key ID (canonical Crockford Base32)
    pub kid: String,

    /// Member ID associated with this key
    pub member_id: String,

    /// Approval timestamp (RFC 3339 UTC, trailing 'Z')
    pub approved_at: String,

    /// Approval method (e.g. "manual-review")
    pub approved_via: KnownKeyApprovalVia,

    /// Optional evidence recorded at approval time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<KnownKeyEvidence>,

    /// Forward-compatible storage for future metadata fields
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Supported approval methods for known keys.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KnownKeyApprovalVia {
    ManualReview,
}

impl fmt::Display for KnownKeyApprovalVia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManualReview => f.write_str("manual-review"),
        }
    }
}

/// Evidence recorded at the time of key approval.
///
/// These are reference values, not cryptographically verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnownKeyEvidence {
    /// GitHub account information at approval time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_account: Option<KnownKeyGithubAccount>,

    /// SSH attestor public key at approval time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_attestor_pub: Option<String>,
}

/// GitHub account information recorded in evidence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnownKeyGithubAccount {
    /// GitHub user ID (numeric)
    pub id: u64,

    /// GitHub login name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
}
