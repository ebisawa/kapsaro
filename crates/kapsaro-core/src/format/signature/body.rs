// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact body byte construction.
//!
//! Provides the typed body bytes shared by MAC and Ed25519 signature inputs.

use crate::format::file::build_file_signature_bytes;
use crate::format::kv::enc::canonical::build_canonical_bytes;
use crate::model::file_enc::FileEncDocumentProtected;
use crate::model::kv_enc::document::KvEncDocument;
use crate::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ArtifactBodyBytes(Vec<u8>);

impl ArtifactBodyBytes {
    pub(crate) fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(bytes.as_ref().to_vec())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) fn build_file_artifact_body_bytes(
    protected: &FileEncDocumentProtected,
) -> Result<ArtifactBodyBytes> {
    build_file_signature_bytes(protected).map(ArtifactBodyBytes)
}

pub(crate) fn build_kv_artifact_body_bytes(document: &KvEncDocument) -> ArtifactBodyBytes {
    ArtifactBodyBytes(build_canonical_bytes(document.lines()))
}

pub(crate) fn build_kv_artifact_body_bytes_from_unsigned(unsigned: &str) -> ArtifactBodyBytes {
    ArtifactBodyBytes::from_bytes(unsigned.as_bytes())
}
