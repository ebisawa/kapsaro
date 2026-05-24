// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Encrypted artifact domain helpers.
//! Provides format-neutral signature, recipient, and wrap-set extraction.

use crate::feature::envelope::wrap_set::WrapSet;
use crate::feature::trust::recipient_sets::{
    encrypted_content_recipient_evidence, ArtifactRecipientEvidence,
};
use crate::feature::verify::file::{verify_file_content, verify_file_content_for_operation};
use crate::feature::verify::kv::signature::{verify_kv_content, verify_kv_content_for_operation};
use crate::format::content::EncContent;
use crate::model::verification::SignatureVerificationProof;
use crate::Result;

pub(crate) fn verify_artifact_signature(
    content: &EncContent,
    debug: bool,
) -> Result<SignatureVerificationProof> {
    match content {
        EncContent::FileEnc(file_content) => {
            let (_, proof) = verify_file_content(file_content, debug)?.into_inner();
            Ok(proof)
        }
        EncContent::KvEnc(kv_content) => {
            let (_, proof) = verify_kv_content(kv_content, debug)?.into_inner();
            Ok(proof)
        }
    }
}

pub(crate) fn verify_artifact_signature_for_operation(
    content: &EncContent,
    debug: bool,
    allow_expired_key: bool,
) -> Result<SignatureVerificationProof> {
    match content {
        EncContent::FileEnc(file_content) => {
            let (_, proof) =
                verify_file_content_for_operation(file_content, debug, allow_expired_key)?
                    .into_inner();
            Ok(proof)
        }
        EncContent::KvEnc(kv_content) => {
            let (_, proof) =
                verify_kv_content_for_operation(kv_content, debug, allow_expired_key)?.into_inner();
            Ok(proof)
        }
    }
}

pub(crate) fn artifact_recipient_evidence(
    content: &EncContent,
) -> Result<ArtifactRecipientEvidence> {
    encrypted_content_recipient_evidence(content)
}

pub(crate) fn artifact_wrap_set(content: &EncContent) -> Result<WrapSet> {
    match content {
        EncContent::FileEnc(file_content) => {
            let doc = file_content.parse()?;
            WrapSet::parse(&doc.protected.wrap, "Document")
        }
        EncContent::KvEnc(kv_content) => {
            let doc = kv_content.parse()?;
            WrapSet::parse(&doc.wrap().wrap, "Document")
        }
    }
}
