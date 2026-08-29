// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verified wrapper types for functional domain modeling
//!
//! This module provides type-level guarantees that documents have passed the
//! required verification or decryption step before trusted operations use them.

use super::private_key::PrivateKeyPlaintext;
use super::verification::SignatureVerificationProof;

/// Proof of successful decryption and validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionProof {
    /// Member handle from the encrypted document
    pub(crate) member_handle: String,
    /// Key statement ID from the encrypted document
    pub(crate) kid: String,
    /// SSH fingerprint used for decryption (None for non-SSH key protection)
    pub(crate) ssh_fpr: Option<String>,
}

// The constructor and the handle/fingerprint accessors below are only reached by
// the first-party test harness through the `cli-test-support` allow-list. Crate
// code reads the fields directly, so allow dead_code when that feature is off.
impl DecryptionProof {
    /// Create a new DecryptionProof.
    #[cfg_attr(not(feature = "cli-test-support"), allow(dead_code))]
    pub fn new(member_handle: String, kid: String, ssh_fpr: Option<String>) -> Self {
        Self {
            member_handle,
            kid,
            ssh_fpr,
        }
    }

    /// Get the member handle.
    #[cfg_attr(not(feature = "cli-test-support"), allow(dead_code))]
    pub fn member_handle(&self) -> &str {
        &self.member_handle
    }

    /// Get the key statement ID.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Get the SSH fingerprint used for decryption.
    #[cfg_attr(not(feature = "cli-test-support"), allow(dead_code))]
    pub fn ssh_fpr(&self) -> Option<&str> {
        self.ssh_fpr.as_deref()
    }
}

/// A document that has been verified to have a valid signature.
///
/// This type ensures that signature verification must occur before the document
/// can be used in operations that require trust. The verification process validates:
/// - The signature is cryptographically valid
/// - The signer's public key is trusted or otherwise accepted by the verification path
/// - For embedded signer_pub, the PublicKey document itself is verified
#[derive(Debug, Clone)]
pub struct VerifiedDocument<T> {
    /// The verified document.
    document: T,
    /// Proof of signature verification.
    proof: SignatureVerificationProof,
}

impl<T> VerifiedDocument<T> {
    /// Create a new verified document wrapper.
    pub fn new(document: T, proof: SignatureVerificationProof) -> Self {
        Self { document, proof }
    }

    /// Get a reference to the verified document.
    pub fn document(&self) -> &T {
        &self.document
    }

    /// Get a reference to the verification proof.
    pub fn proof(&self) -> &SignatureVerificationProof {
        &self.proof
    }

    /// Get a mutable reference to the verification proof.
    pub(crate) fn proof_mut(&mut self) -> &mut SignatureVerificationProof {
        &mut self.proof
    }

    /// Extract the inner document and proof (consumes self).
    pub fn into_inner(self) -> (T, SignatureVerificationProof) {
        (self.document, self.proof)
    }
}

/// A PrivateKeyPlaintext that has been successfully decrypted and validated
///
/// This type ensures that decryption and validation must occur before the plaintext
/// can be used in operations that require trust (e.g., unwrapping master keys).
/// The validation process checks:
/// - Key material structure (crv, kty, key lengths)
/// - Cryptographic consistency (e.g., private/public key pairs match)
/// - SSH fingerprint matches the decryption key
///
/// Loading a key context is the only way to obtain one. The accompanying
/// [`DecryptionProof`] records which member handle, key statement, and SSH
/// fingerprint the decryption ran under, so callers can report the identity
/// they actually decrypted with rather than the one they asked for.
#[derive(Debug)]
pub struct VerifiedPrivateKey {
    /// The decrypted document
    pub(crate) document: PrivateKeyPlaintext,
    /// Proof of decryption and validation
    pub(crate) proof: DecryptionProof,
}
impl VerifiedPrivateKey {
    /// Create a new VerifiedPrivateKey wrapper
    pub fn new(document: PrivateKeyPlaintext, proof: DecryptionProof) -> Self {
        Self { document, proof }
    }

    /// Get a reference to the decrypted document
    pub fn document(&self) -> &PrivateKeyPlaintext {
        &self.document
    }

    /// Get a reference to the decryption proof
    pub fn proof(&self) -> &DecryptionProof {
        &self.proof
    }
}
