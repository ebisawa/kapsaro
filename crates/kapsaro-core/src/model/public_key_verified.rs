// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verified wrappers for public-key-related domain models.

use super::public_key::{IdentityKeys, PublicKey};
use super::verification::{ExpiryProof, SelfSignatureProof};
use ed25519_dalek::VerifyingKey;

/// Proof of SSH attestation verification.
///
/// A marker: the attestation check leaves nothing a caller reads back, so the
/// proof carries only the fact that it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationProof(
    // Never read: the private field is what keeps the proof unconstructible
    // outside the crate, which is the whole of what it states.
    #[allow(dead_code)] (),
);

impl AttestationProof {
    /// Create a new AttestationProof.
    ///
    /// Kept out of the crate's external surface: the proof states that the
    /// attestation check ran, so it is minted where that check happens.
    pub(crate) fn new() -> Self {
        Self(())
    }
}

/// Public key statement verified to have a valid SSH attestation.
#[derive(Debug, Clone)]
pub struct AttestedKeyStatement {
    // Never read: carrying the attested keys together with their proof is what
    // makes this statement unconstructible without an attestation check.
    #[allow(dead_code)]
    keys: IdentityKeys,
    #[allow(dead_code)]
    proof: AttestationProof,
}

impl AttestedKeyStatement {
    /// Create a new AttestedKeyStatement.
    ///
    /// Kept out of the crate's external surface: a statement becomes attested
    /// where the attestation check ran, not wherever the keys are held.
    pub(crate) fn new(keys: IdentityKeys, proof: AttestationProof) -> Self {
        Self { keys, proof }
    }
}

/// PublicKey verified for both self-signature and attestation.
#[derive(Debug, Clone)]
pub struct VerifiedPublicKeyAttested {
    document: PublicKey,
    // Never read: holding both proofs is what makes this type unconstructible
    // without a self-signature check and an attestation check, which is the
    // guarantee the type exists for.
    #[allow(dead_code)]
    self_signature_proof: SelfSignatureProof,
    #[allow(dead_code)]
    statement: AttestedKeyStatement,
}
impl VerifiedPublicKeyAttested {
    /// Create a new VerifiedPublicKeyAttested.
    ///
    /// Kept out of the crate's external surface: a document becomes verified
    /// where the self-signature and attestation checks ran.
    pub(crate) fn new(
        document: PublicKey,
        self_signature_proof: SelfSignatureProof,
        statement: AttestedKeyStatement,
    ) -> Self {
        Self {
            document,
            self_signature_proof,
            statement,
        }
    }

    /// Get a reference to the verified document.
    pub fn document(&self) -> &PublicKey {
        &self.document
    }
}

/// PublicKey verified for signature verification use.
#[derive(Debug, Clone)]
pub struct VerifiedSigningPublicKey {
    attested: VerifiedPublicKeyAttested,
    verifying_key: VerifyingKey,
}

impl VerifiedSigningPublicKey {
    /// Construct from an attested key and its verified Ed25519 key material.
    ///
    /// Kept out of the crate's external surface: the key material is the one
    /// the self-signature check verified with.
    pub(crate) fn new(attested: VerifiedPublicKeyAttested, verifying_key: VerifyingKey) -> Self {
        Self {
            attested,
            verifying_key,
        }
    }

    /// Get a reference to the verified document.
    pub fn document(&self) -> &PublicKey {
        self.attested.document()
    }

    /// Get a reference to the attested key wrapper.
    pub fn attested(&self) -> &VerifiedPublicKeyAttested {
        &self.attested
    }

    /// Get the verified Ed25519 key material for signature verification.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

/// Recipient public key verified for self-signature, attestation, and expiry.
///
/// Required for wrap (encryption) operations. Cannot be constructed without
/// passing the expiry check, providing a compile-time guarantee that expired
/// keys cannot be used as encryption recipients.
#[derive(Debug, Clone)]
pub struct VerifiedRecipientKey {
    verified: VerifiedPublicKeyAttested,
    // Never read: holding the proof is what makes this type unconstructible
    // without an expiry check, which is the guarantee the type exists for.
    #[allow(dead_code)]
    expiry_proof: ExpiryProof,
}

impl VerifiedRecipientKey {
    /// Construct from a verified-and-attested key plus expiry proof.
    ///
    /// Kept out of the crate's external surface: a key becomes a recipient
    /// where the expiry check ran.
    pub(crate) fn new(verified: VerifiedPublicKeyAttested, expiry_proof: ExpiryProof) -> Self {
        Self {
            verified,
            expiry_proof,
        }
    }

    /// Get a reference to the verified document.
    pub fn document(&self) -> &PublicKey {
        self.verified.document()
    }

    pub fn attested(&self) -> &VerifiedPublicKeyAttested {
        &self.verified
    }
}
