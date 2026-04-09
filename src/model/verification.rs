// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verification proof types for functional domain modeling
//!
//! This module provides proof types that represent the result of verification operations.
//! These proofs are used in state wrappers to ensure type-level guarantees.

use crate::model::public_key::PublicKey;

/// Proof of PublicKey self-signature verification
///
/// This proof indicates that the PublicKey document's self-signature has been
/// cryptographically verified. Used in `VerifiedPublicKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSignatureProof {}

impl SelfSignatureProof {
    /// Create a new SelfSignatureProof
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SelfSignatureProof {
    fn default() -> Self {
        Self::new()
    }
}

/// Proof that key expiration has been checked for write operations.
///
/// This proof indicates that the PublicKey's expiration date has been validated
/// and the key is not expired. Used in `VerifiedRecipientKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryProof {}

impl ExpiryProof {
    /// Create a new ExpiryProof
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for ExpiryProof {
    fn default() -> Self {
        Self::new()
    }
}

/// Source of verifying key for signature verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyingKeySource {
    /// PublicKey was embedded in signature.signer_pub
    SignerPubEmbedded,
}

/// Proof of signature verification
///
/// This proof contains information about the verified signer and how
/// the verifying key was obtained. It is used in `VerifiedFileEncDocument`
/// and `VerifiedKvEncDocument` to provide type-level guarantees that
/// signature verification has occurred.
#[derive(Debug, Clone, PartialEq)]
pub struct SignatureVerificationProof {
    /// Signer's member ID (verified)
    pub member_id: String,
    /// Key statement ID of the signing key
    pub kid: String,
    /// Embedded signer public key used for cryptographic verification
    pub signer_public_key: Option<PublicKey>,
    /// Source of the verifying key
    pub verifying_key_source: VerifyingKeySource,
    /// Warnings (e.g., expired key used for verification)
    pub warnings: Vec<String>,
}

impl SignatureVerificationProof {
    /// Create a new SignatureVerificationProof
    pub fn new(
        member_id: String,
        kid: String,
        verifying_key_source: VerifyingKeySource,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            member_id,
            kid,
            signer_public_key: None,
            verifying_key_source,
            warnings,
        }
    }

    /// Create a new SignatureVerificationProof with embedded signer metadata.
    pub fn new_with_signer_public_key(
        member_id: String,
        kid: String,
        signer_public_key: PublicKey,
        verifying_key_source: VerifyingKeySource,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            member_id,
            kid,
            signer_public_key: Some(signer_public_key),
            verifying_key_source,
            warnings,
        }
    }
}

/// Proof of binding_claims online verification
///
/// This proof indicates that the document's binding_claims (e.g. github_account)
/// have been verified against an external service (e.g. GitHub API). Used in
/// `VerifiedBindingClaims`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingVerificationProof {
    /// Verification method (e.g. "github")
    pub method: String,
    /// SSH key fingerprint that was matched (when applicable)
    pub fingerprint: Option<String>,
    /// External service key id (e.g. GitHub key id) when matched
    pub matched_key_id: Option<i64>,
}
impl BindingVerificationProof {
    /// Create a new BindingVerificationProof
    pub fn new(method: String, fingerprint: Option<String>, matched_key_id: Option<i64>) -> Self {
        Self {
            method,
            fingerprint,
            matched_key_id,
        }
    }
}
