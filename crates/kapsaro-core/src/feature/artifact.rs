// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Encrypted artifact domain helpers.
//! Provides format-neutral signature, recipient, and wrap-set extraction.

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
) -> Result<SignatureVerificationProof> {
    match content {
        EncContent::FileEnc(file_content) => {
            let (_, proof) = verify_file_content(file_content)?.into_inner();
            Ok(proof)
        }
        EncContent::KvEnc(kv_content) => {
            let (_, proof) = verify_kv_content(kv_content)?.into_inner();
            Ok(proof)
        }
    }
}

pub(crate) fn verify_artifact_signature_for_operation(
    content: &EncContent,
    allow_expired_key: bool,
) -> Result<SignatureVerificationProof> {
    match content {
        EncContent::FileEnc(file_content) => {
            let (_, proof) =
                verify_file_content_for_operation(file_content, allow_expired_key)?.into_inner();
            Ok(proof)
        }
        EncContent::KvEnc(kv_content) => {
            let (_, proof) =
                verify_kv_content_for_operation(kv_content, allow_expired_key)?.into_inner();
            Ok(proof)
        }
    }
}

pub(crate) fn artifact_recipient_evidence(
    content: &EncContent,
) -> Result<ArtifactRecipientEvidence> {
    encrypted_content_recipient_evidence(content)
}
