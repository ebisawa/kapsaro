// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public encrypted-artifact inspection API.
//! Re-exports semantic inspection results without CLI path rendering.

pub use crate::service::inspect::{
    inspect_file, AeadAlgorithmMetadata, ArtifactSignatureMetadata, AttestationMetadata,
    BindingClaimsMetadata, FileEncHeaderMetadata, FileEncInspectMetadata, FilePayloadMetadata,
    FilePayloadProtectedMetadata, GithubAccountMetadata, IdentityKeysMetadata, InspectMetadata,
    InspectResult, JwkPublicKeyMetadata, KvEncInspectMetadata, KvEntryMetadata, KvHeaderMetadata,
    KvSummaryMetadata, OnlineVerificationMetadata, PayloadCiphertextMetadata,
    RemovedRecipientMetadata, SignatureVerificationMetadata, SignerPublicKeyMetadata,
    SignerPublicKeyProtectedMetadata, WrapDataMetadata, WrapItemMetadata,
};
