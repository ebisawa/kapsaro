// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verified wrappers for public-key-related domain models.

use super::public_key::{BindingClaims, IdentityKeys, PublicKey};
use super::verification::{BindingVerificationProof, ExpiryProof, SelfSignatureProof};
use ed25519_dalek::VerifyingKey;

/// Binding claims that have been verified online (e.g. via member verify).
#[derive(Debug, Clone)]
pub struct VerifiedBindingClaims {
    /// The verified binding claims
    pub claims: BindingClaims,
    /// Proof of online verification
    pub proof: BindingVerificationProof,
}

impl VerifiedBindingClaims {
    /// Create a new VerifiedBindingClaims.
    pub fn new(claims: BindingClaims, proof: BindingVerificationProof) -> Self {
        Self { claims, proof }
    }

    /// Get a reference to the verified claims.
    pub fn claims(&self) -> &BindingClaims {
        &self.claims
    }

    /// Get a reference to the verification proof.
    pub fn proof(&self) -> &BindingVerificationProof {
        &self.proof
    }
}

/// Proof of SSH attestation verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationProof {
    /// Attestation method (e.g., "ssh-sign")
    pub method: String,
    /// SSH public key used for attestation (from attestation.pub)
    pub ssh_pub: String,
    /// Optional verification timestamp (RFC 3339)
    #[allow(dead_code)]
    pub verified_at: Option<String>,
}

/// Public key statement verified to have a valid SSH attestation.
#[derive(Debug, Clone)]
pub struct AttestedKeyStatement {
    /// Public keys covered by the attested statement.
    pub keys: IdentityKeys,
    /// Proof of attestation verification
    pub proof: AttestationProof,
}

impl AttestedKeyStatement {
    /// Create a new AttestedKeyStatement.
    pub fn new(keys: IdentityKeys, proof: AttestationProof) -> Self {
        Self { keys, proof }
    }
}

/// PublicKey verified for both self-signature and attestation.
#[derive(Debug, Clone)]
pub struct VerifiedPublicKeyAttested {
    /// The verified document
    pub document: PublicKey,
    /// Proof of self-signature verification
    pub self_signature_proof: SelfSignatureProof,
    /// Attestation-verified key statement.
    pub statement: AttestedKeyStatement,
}
impl VerifiedPublicKeyAttested {
    /// Create a new VerifiedPublicKeyAttested.
    pub fn new(
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

    /// Get a reference to the attestation-verified key statement.
    pub fn statement(&self) -> &AttestedKeyStatement {
        &self.statement
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
    pub fn new(attested: VerifiedPublicKeyAttested, verifying_key: VerifyingKey) -> Self {
        Self {
            attested,
            verifying_key,
        }
    }

    /// Get a reference to the verified document.
    pub fn document(&self) -> &PublicKey {
        self.attested.document()
    }

    /// Get a reference to the attestation-verified key statement.
    pub fn statement(&self) -> &AttestedKeyStatement {
        self.attested.statement()
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
    #[allow(dead_code)]
    expiry_proof: ExpiryProof,
}

impl VerifiedRecipientKey {
    /// Construct from a verified-and-attested key plus expiry proof.
    pub fn new(verified: VerifiedPublicKeyAttested, expiry_proof: ExpiryProof) -> Self {
        Self {
            verified,
            expiry_proof,
        }
    }

    /// Get a reference to the verified document.
    pub fn document(&self) -> &PublicKey {
        self.verified.document()
    }

    /// Get a reference to the attestation-verified key statement.
    pub fn statement(&self) -> &AttestedKeyStatement {
        self.verified.statement()
    }

    pub fn attested(&self) -> &VerifiedPublicKeyAttested {
        &self.verified
    }
}
