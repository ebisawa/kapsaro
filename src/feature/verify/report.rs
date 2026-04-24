// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature verification report generation

use super::key_loader::SignatureVerificationKey;
use super::SignatureVerificationReport;
use crate::model::public_key::PublicKey;
use crate::model::verification::VerifyingKeySource;
use crate::Result;

/// Build an error verification report.
pub(crate) fn build_error_report(message: String) -> SignatureVerificationReport {
    SignatureVerificationReport {
        verified: false,
        signer_member_id: None,
        source: None,
        warnings: Vec::new(),
        message,
        signer_public_key: None,
    }
}

/// Build a success verification report.
pub(crate) fn build_success_report(
    member_id: String,
    source: VerifyingKeySource,
    warnings: Vec<String>,
    signer_public_key: PublicKey,
) -> SignatureVerificationReport {
    SignatureVerificationReport {
        verified: true,
        signer_member_id: Some(member_id),
        source: Some(source),
        warnings,
        message: "OK".to_string(),
        signer_public_key: Some(signer_public_key),
    }
}

pub(crate) fn build_success_report_from_loaded_key(
    loaded: SignatureVerificationKey,
) -> SignatureVerificationReport {
    build_success_report(
        loaded.member_id,
        loaded.source,
        loaded.warnings,
        loaded.public_key,
    )
}

pub(crate) fn build_signature_verification_report<Verify>(
    loaded: Result<SignatureVerificationKey>,
    verify: Verify,
) -> SignatureVerificationReport
where
    Verify: FnOnce(&SignatureVerificationKey) -> Result<()>,
{
    match loaded {
        Ok(loaded) => match verify(&loaded) {
            Ok(()) => build_success_report_from_loaded_key(loaded),
            Err(e) => build_error_report(e.format_user_message().to_string()),
        },
        Err(e) => build_error_report(e.format_user_message().to_string()),
    }
}
