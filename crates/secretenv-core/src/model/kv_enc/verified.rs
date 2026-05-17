// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::model::kv_enc::document::KvEncDocument;
use crate::model::verification::SignatureVerificationProof;

#[derive(Debug, Clone)]
pub struct VerifiedKvEncDocument {
    pub document: KvEncDocument,
    pub proof: SignatureVerificationProof,
}

impl VerifiedKvEncDocument {
    pub fn new(document: KvEncDocument, proof: SignatureVerificationProof) -> Self {
        Self { document, proof }
    }

    pub fn document(&self) -> &KvEncDocument {
        &self.document
    }

    pub fn proof(&self) -> &SignatureVerificationProof {
        &self.proof
    }

    pub fn into_inner(self) -> (KvEncDocument, SignatureVerificationProof) {
        (self.document, self.proof)
    }
}
