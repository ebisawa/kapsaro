// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verified wrapper for Local Trust Store documents.

use super::trust_store::TrustStoreDocument;

/// Proof that a Trust Store document has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustStoreVerificationProof {
    /// Owner member handle confirmed by verification
    pub owner_handle: String,
}

impl TrustStoreVerificationProof {
    /// Create a new TrustStoreVerificationProof.
    ///
    /// Kept out of the crate's external surface: a proof states that the trust
    /// store verification ran, so it is minted where that check happens.
    pub(crate) fn new(owner_handle: String) -> Self {
        Self { owner_handle }
    }
}

/// A Trust Store document that has been verified.
///
/// Verification confirms:
/// - JSON Schema validity
/// - Cryptographic signature correctness
/// - local keystore public key validity and kid/owner consistency
/// - known_keys uniqueness constraints
/// - recipient_sets integrity constraints
#[derive(Debug, Clone)]
pub struct VerifiedTrustStore {
    document: TrustStoreDocument,
    proof: TrustStoreVerificationProof,
}

impl VerifiedTrustStore {
    /// Create a new VerifiedTrustStore wrapper.
    ///
    /// Kept out of the crate's external surface: a document becomes verified
    /// where the checks listed above actually ran, not wherever one is held.
    pub(crate) fn new(document: TrustStoreDocument, proof: TrustStoreVerificationProof) -> Self {
        Self { document, proof }
    }

    /// Get a reference to the verified document.
    pub fn document(&self) -> &TrustStoreDocument {
        &self.document
    }

    /// Extract the inner document and proof (consumes self).
    pub fn into_inner(self) -> (TrustStoreDocument, TrustStoreVerificationProof) {
        (self.document, self.proof)
    }
}
