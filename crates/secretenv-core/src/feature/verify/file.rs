// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File-enc signature verification.

use super::SignatureVerificationReport;
use crate::feature::envelope::signature::verify_file_signature;
use crate::format::content::FileEncContent;
use crate::model::common::validate_wrap_items;
use crate::model::file_enc::FileEncDocument;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::Result;

use super::key_loader::load_verifying_key_from_signature;
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

/// Verify signature of FileEncDocument and return report for display.
pub fn verify_file_document_report(
    doc: &FileEncDocument,
    debug: bool,
) -> SignatureVerificationReport {
    let signature = &doc.signature;
    let protected = doc.extract_protected_for_signing();
    build_signature_verification_report(
        load_verifying_key_from_signature(signature, debug),
        |loaded| verify_file_signature(protected, &loaded.verifying_key, signature, debug),
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
        verify_file_signature(protected, &loaded.verifying_key, signature, debug)
    })?;

    Ok(VerifiedFileEncDocument::new(doc.clone(), proof))
}
