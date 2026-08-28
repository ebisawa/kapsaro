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
/// cryptographically verified. Used by verified public-key wrappers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSignatureProof(
    // Never read: the private field is what keeps the proof unconstructible
    // outside the crate, which is the whole of what it states.
    #[allow(dead_code)] (),
);

impl SelfSignatureProof {
    /// Create a new SelfSignatureProof.
    ///
    /// Kept out of the crate's external surface: the proof states that the
    /// self-signature check ran, so it is minted where that check happens.
    pub(crate) fn new() -> Self {
        Self(())
    }
}

/// Proof that key expiration has been checked for write operations.
///
/// This proof indicates that the PublicKey's expiration date has been validated
/// and the key is not expired. Used in `VerifiedRecipientKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryProof(
    // Never read: see `SelfSignatureProof`.
    #[allow(dead_code)] (),
);

impl ExpiryProof {
    /// Create a new ExpiryProof.
    ///
    /// Kept out of the crate's external surface: the proof states that the
    /// expiry check ran, so it is minted where that check happens.
    pub(crate) fn new() -> Self {
        Self(())
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
    /// Signer's member handle (verified)
    pub member_handle: String,
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
    /// Create a new SignatureVerificationProof with embedded signer metadata.
    ///
    /// Signature verification always carries the key it verified with, so the
    /// embedded key is required rather than optional here.
    pub fn new_with_signer_public_key(
        member_handle: String,
        kid: String,
        signer_public_key: PublicKey,
        verifying_key_source: VerifyingKeySource,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            member_handle,
            kid,
            signer_public_key: Some(signer_public_key),
            verifying_key_source,
            warnings,
        }
    }
}
