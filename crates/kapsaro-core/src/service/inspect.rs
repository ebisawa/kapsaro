// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Builds semantic inspection results for encrypted artifacts.
//! Leaves input-path display and terminal rendering to callers.

use std::path::Path;

use crate::Result;

mod collection;
mod metadata;

pub use metadata::{
    AeadAlgorithmMetadata, ArtifactSignatureMetadata, AttestationMetadata, BindingClaimsMetadata,
    FileEncHeaderMetadata, FileEncInspectMetadata, FilePayloadMetadata,
    FilePayloadProtectedMetadata, GithubAccountMetadata, IdentityKeysMetadata, InspectMetadata,
    JwkPublicKeyMetadata, KvEncInspectMetadata, KvEntryMetadata, KvHeaderMetadata,
    KvSummaryMetadata, OnlineVerificationMetadata, PayloadCiphertextMetadata,
    RemovedRecipientMetadata, SignatureVerificationMetadata, SignerPublicKeyMetadata,
    SignerPublicKeyProtectedMetadata, WrapDataMetadata, WrapItemMetadata,
};

use collection::{build_online_output, build_signature_report, load_inspect_content};
use metadata::build_inspect_metadata;

pub struct InspectResult {
    pub metadata: InspectMetadata,
}

/// Online verification display variants.
pub enum OnlineVerificationDisplay {
    /// GitHub verification result available.
    GithubResult(crate::io::verify_online::VerificationResult),
    /// Binding claims exist but no supported binding is configured.
    NoSupportedBinding,
}

pub fn inspect_file(input_path: &Path) -> Result<InspectResult> {
    let content = load_inspect_content(input_path)?;
    let signature_report = build_signature_report(&content)?;
    let online_output = build_online_output(&signature_report);
    let metadata = build_inspect_metadata(&content, &signature_report, online_output)?;
    Ok(InspectResult { metadata })
}
