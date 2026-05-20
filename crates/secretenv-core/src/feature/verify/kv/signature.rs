// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::envelope::signature::verify_kv_signature;
use crate::feature::verify::append_operational_signer_expiry_warning;
use crate::feature::verify::key_loader::load_verifying_key_from_signature;
use crate::feature::verify::report::{build_error_report, build_signature_verification_report};
use crate::feature::verify::signature::verify_signature_with_loaded_key;
use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::KvEncContent;
use crate::format::kv::document::parse_kv_document;
use crate::model::common::validate_wrap_items;
use crate::model::kv_enc::document::KvEncDocument;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::Result;

pub fn verify_kv_content(content: &KvEncContent, debug: bool) -> Result<VerifiedKvEncDocument> {
    let doc = content.parse()?;
    verify_kv_document(&doc, debug)
}

pub fn verify_kv_content_for_operation(
    content: &KvEncContent,
    debug: bool,
    allow_expired_key: bool,
) -> Result<VerifiedKvEncDocument> {
    let mut verified = verify_kv_content(content, debug)?;
    append_operational_signer_expiry_warning(&mut verified.proof, allow_expired_key)?;
    Ok(verified)
}

pub fn verify_kv_document_report(content: &str, debug: bool) -> SignatureVerificationReport {
    match parse_kv_document(content) {
        Ok(doc) => {
            let signature = doc.signature();
            build_signature_verification_report(
                load_verifying_key_from_signature(signature, debug),
                |loaded| verify_kv_signature(&doc, &loaded.verifying_key, signature, debug),
            )
        }
        Err(e) => build_error_report(e.format_user_message().to_string()),
    }
}

pub fn verify_kv_document(doc: &KvEncDocument, debug: bool) -> Result<VerifiedKvEncDocument> {
    validate_wrap_items(&doc.wrap.wrap, "Document")?;
    let signature = doc.signature();
    let proof = verify_signature_with_loaded_key(signature, debug, |loaded| {
        verify_kv_signature(doc, &loaded.verifying_key, signature, debug)
    })?;

    Ok(VerifiedKvEncDocument::new(doc.clone(), proof))
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/feature_verify_kv_operation_test.rs"]
mod tests;
