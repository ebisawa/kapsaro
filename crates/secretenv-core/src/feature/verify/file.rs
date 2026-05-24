// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File-enc signature verification.

use super::{append_operational_signer_expiry_warning, SignatureVerificationReport};
use crate::feature::envelope::signature::verify_file_signature;
use crate::format::content::FileEncContent;
use crate::format::wrap::validate_wrap_items;
use crate::model::file_enc::FileEncDocument;
use crate::model::file_enc::FileEncDocumentProtected;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::signature::ArtifactSignature;
use crate::Result;

use super::key_loader::{load_verifying_key_from_signature, SignatureVerificationKey};
use super::report::build_signature_verification_report;
use super::signature::verify_signature_with_loaded_key;

/// Parse and verify file-enc content.
pub fn verify_file_content(
    content: &FileEncContent,
    debug: bool,
) -> Result<VerifiedFileEncDocument> {
    let doc = content.parse()?;
    verify_file_document(&doc, debug)
}

/// Parse and verify file-enc content with operational expired-key policy.
pub fn verify_file_content_for_operation(
    content: &FileEncContent,
    debug: bool,
    allow_expired_key: bool,
) -> Result<VerifiedFileEncDocument> {
    let mut verified = verify_file_content(content, debug)?;
    append_operational_signer_expiry_warning(&mut verified.proof, allow_expired_key)?;
    Ok(verified)
}

/// Verify signature of FileEncDocument and return report for display.
pub fn verify_file_document_report(
    doc: &FileEncDocument,
    debug: bool,
) -> SignatureVerificationReport {
    let signature = &doc.signature;
    let protected = doc.extract_protected_for_signing();
    build_signature_verification_report(
        load_verifying_key_from_signature(signature, debug),
        |loaded| verify_loaded_file_signature(protected, signature, loaded, debug),
    )
}

/// Verify signature of FileEncDocument and return VerifiedFileEncDocument wrapper.
///
/// Returns `Ok(VerifiedFileEncDocument)` if signature is valid, error otherwise.
pub fn verify_file_document(doc: &FileEncDocument, debug: bool) -> Result<VerifiedFileEncDocument> {
    validate_wrap_items(&doc.protected.wrap, "Document")?;
    let signature = &doc.signature;
    let protected = doc.extract_protected_for_signing();
    let proof = verify_signature_with_loaded_key(signature, debug, |loaded| {
        verify_loaded_file_signature(protected, signature, loaded, debug)
    })?;

    Ok(VerifiedFileEncDocument::new(doc.clone(), proof))
}

fn verify_loaded_file_signature(
    protected: &FileEncDocumentProtected,
    signature: &ArtifactSignature,
    loaded: &SignatureVerificationKey,
    debug: bool,
) -> Result<()> {
    verify_file_signature(protected, &loaded.verifying_key, signature, debug)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_verify_file_operation_test.rs"]
mod tests;
