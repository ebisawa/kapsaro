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

impl DecryptionProof {
    /// Create a new DecryptionProof.
    pub fn new(member_handle: String, kid: String, ssh_fpr: Option<String>) -> Self {
        Self {
            member_handle,
            kid,
            ssh_fpr,
        }
    }

    /// Get the member handle.
    pub fn member_handle(&self) -> &str {
        &self.member_handle
    }

    /// Get the key statement ID.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Get the SSH fingerprint used for decryption.
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
/// # Example
///
/// ```ignore
/// use kapsaro_core::model::verified::VerifiedPrivateKey;
/// use kapsaro_core::model::private_key::PrivateKeyPlaintext;
/// use kapsaro_core::io::ssh::backend::SignatureBackend;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Load member key context (returns CryptoContext with VerifiedPrivateKey)
/// # let member_handle = "alice@example.com";
/// # let backend: &dyn SignatureBackend = todo!();
/// # let ssh_pubkey = "";
/// # let keystore_root = std::path::PathBuf::from("/tmp");
/// # let debug = false;
/// # let load_crypto_context = |_member_handle: &str,
/// #                            _backend: &dyn SignatureBackend,
/// #                            _ssh_pubkey: &str,
/// #                            _explicit_kid: Option<&str>,
/// #                            _keystore_root: Option<&std::path::PathBuf>,
/// #                            _workspace_path: Option<std::path::PathBuf>,
/// #                            _debug: bool|
/// #  -> Result<{ kapsaro_core::feature::context::crypto::CryptoContext }, Box<dyn std::error::Error>> { todo!() };
/// let key_ctx = load_crypto_context(
///     member_handle,
///     backend,
///     ssh_pubkey,
///     None,
///     Some(&keystore_root),
///     None,
///     debug,
/// )?;
///
/// // Access decrypted document and proof information
/// let plaintext = key_ctx.private_key.document();
/// let proof = key_ctx.private_key.proof();
/// assert_eq!(proof.member_handle(), "alice@example.com");
///
/// // The VerifiedPrivateKey wrapper ensures type-level guarantees that decryption
/// // and validation have occurred before the plaintext can be used in trusted operations.
/// # Ok(())
/// # }
/// ```
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

    /// Extract the inner document and proof (consumes self)
    pub fn into_inner(self) -> (PrivateKeyPlaintext, DecryptionProof) {
        (self.document, self.proof)
    }

    /// Map the inner document while preserving decryption status
    pub fn map<F>(self, f: F) -> VerifiedPrivateKey
    where
        F: FnOnce(PrivateKeyPlaintext) -> PrivateKeyPlaintext,
    {
        VerifiedPrivateKey {
            document: f(self.document),
            proof: self.proof,
        }
    }
}
