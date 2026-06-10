// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! FileEncDocument v7 model
//!
//! Format: kapsaro:format:file-enc@1
//! Used for encrypting arbitrary files with v5 format

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::{RemovedRecipient, WrapItem};
use super::signature::ArtifactSignature;
use super::verification::SignatureVerificationProof;

/// FileEncDocument v7 top-level structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileEncDocument {
    /// Protected content (signature target)
    pub protected: FileEncDocumentProtected,
    /// Signature over protected object
    pub signature: ArtifactSignature,
}

/// FileEncDocument protected object (signature target)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileEncDocumentProtected {
    /// Format identifier: "kapsaro:format:file-enc@1"
    pub format: String,

    /// Secret identifier (UUID)
    pub sid: Uuid,

    /// Wrapped keys (one per recipient)
    pub wrap: Vec<WrapItem>,

    /// Removed recipients history
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_recipients: Option<Vec<RemovedRecipient>>,

    /// Payload envelope
    pub payload: FilePayload,

    /// Creation timestamp (RFC 3339)
    pub created_at: String,

    /// Update timestamp (RFC 3339)
    pub updated_at: String,
}

impl FileEncDocumentProtected {
    /// Derives the list of recipients from wrap items
    pub fn recipients(&self) -> Vec<String> {
        self.wrap
            .iter()
            .map(|w| w.recipient_handle.clone())
            .collect()
    }
}

/// File payload envelope (protected + encrypted)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FilePayload {
    /// Protected header (AAD source)
    pub protected: FilePayloadHeader,
    /// Encrypted data
    pub encrypted: FilePayloadCiphertext,
}

/// File payload protected header
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FilePayloadHeader {
    /// Format identifier: "kapsaro:format:file-enc:payload@1"
    pub format: String,
    /// Secret identifier (UUID). Must match the outer `protected.sid`
    pub sid: Uuid,
    /// Algorithm specification
    pub alg: FileEncAlgorithm,
}

/// File payload algorithm specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileEncAlgorithm {
    /// AEAD algorithm: "xchacha20-poly1305"
    pub aead: String,
}

/// File payload encrypted data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FilePayloadCiphertext {
    /// Nonce (base64url, 24 bytes for XChaCha20-Poly1305)
    pub nonce: String,
    /// Ciphertext (base64url, includes authentication tag)
    #[serde(rename = "ct")]
    pub ct: String,
}

impl FileEncDocument {
    /// Returns a reference to the protected object for signature generation
    pub fn extract_protected_for_signing(&self) -> &FileEncDocumentProtected {
        &self.protected
    }

    /// Derives the list of recipients from wrap items
    pub fn recipients(&self) -> Vec<String> {
        self.protected.recipients()
    }
}

/// A FileEncDocument that has been verified to have a valid signature
///
/// This type ensures that signature verification must occur before the document
/// can be used in operations that require trust (e.g., decryption).
/// The verification process validates:
/// - The signature is cryptographically valid
/// - The signer's public key is trusted (either embedded and verified,
///   or found in keystore)
/// - For embedded signer_pub, the PublicKey document itself is verified
///
/// # Example
///
/// ```ignore
/// use kapsaro_core::model::file_enc::{FileEncDocument, VerifiedFileEncDocument};
/// use kapsaro_core::feature::verify::file::verify_file_document;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse unverified document
/// # let json = "{}";
/// # let debug = false;
/// let doc: FileEncDocument = serde_json::from_str(json)?;
///
/// // Verify signature (returns VerifiedFileEncDocument)
/// let verified = verify_file_document(&doc, debug)?;
///
/// // Access verified document and proof information
/// let document = verified.document();
/// let proof = verified.proof();
/// assert_eq!(proof.member_handle, "alice");
///
/// // The VerifiedFileEncDocument wrapper ensures type-level guarantees that verification
/// // has occurred before the document can be used in trusted operations.
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedFileEncDocument {
    /// The verified document
    document: FileEncDocument,
    /// Proof of signature verification
    proof: SignatureVerificationProof,
}
impl VerifiedFileEncDocument {
    /// Create a new VerifiedFileEncDocument wrapper
    pub fn new(document: FileEncDocument, proof: SignatureVerificationProof) -> Self {
        Self { document, proof }
    }

    /// Get a reference to the verified document
    pub fn document(&self) -> &FileEncDocument {
        &self.document
    }

    /// Get a reference to the verification proof
    pub fn proof(&self) -> &SignatureVerificationProof {
        &self.proof
    }

    /// Get a mutable reference to the verification proof
    pub(crate) fn proof_mut(&mut self) -> &mut SignatureVerificationProof {
        &mut self.proof
    }

    /// Extract the inner document and proof (consumes self)
    pub fn into_inner(self) -> (FileEncDocument, SignatureVerificationProof) {
        (self.document, self.proof)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/model_file_enc_test.rs"]
mod model_file_enc_test;

#[cfg(test)]
#[path = "../../tests/unit/internal/model_verified_test.rs"]
mod model_verified_test;
