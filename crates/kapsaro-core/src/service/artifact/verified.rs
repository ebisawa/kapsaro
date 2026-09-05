// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared abstraction over signature-verified file-enc and kv-enc artifacts.
//! Lets trust evaluation, read binding, and rewrap run once for both formats.

use std::borrow::Cow;

use crate::feature::context::crypto::DecryptionKeyInfo;
use crate::format::content::EncContent;
use crate::model::common::WrapItem;
use crate::model::verification::SignatureVerificationProof;
use crate::service::key::KeyContext;
use crate::service::operation::OperationOptions;
use crate::service::trust::{ReadTrustExceptions, RecipientSetSubject};
use crate::Result;

/// Artifact kind bound into review and acceptance state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncArtifactKind {
    File,
    Kv,
}

/// Signature-verified artifact whose trust evaluation and key binding are
/// shared by file-enc and kv-enc callers.
pub(crate) trait VerifiedEncArtifact: Clone + Sized {
    const KIND: EncArtifactKind;

    /// Parse serialized artifact text and verify its signature.
    fn verify_text(text: &str, options: OperationOptions) -> Result<Self>;

    /// Return the digest that binds one review to the exact reviewed bytes.
    fn binding_digest(&self) -> [u8; 32];

    /// Return the signature verification proof produced by verification.
    fn proof(&self) -> &SignatureVerificationProof;

    /// Extract the recipient-set subject for trust policy evaluation.
    fn recipient_set_subject(&self) -> Result<RecipientSetSubject>;

    /// Return the recipient wrap items used for decryption-key expiry checks.
    fn wrap_items(&self) -> &[WrapItem];

    /// Unwrap the caller's master key and verify key possession.
    fn verify_key_possession(&self, key_ctx: &KeyContext) -> Result<DecryptionKeyInfo>;

    /// Consume the verified artifact into the content rewrap rewrites.
    fn into_enc_content(self) -> EncContent;
}

/// Verified artifact that one read operation can bind as a trusted capability.
pub(crate) trait ReadableEncArtifact: VerifiedEncArtifact {
    type Operation: Clone;
    type Trusted<'a>
    where
        Self: 'a;

    /// Reject exception combinations the read operation forbids.
    fn enforce_read_exceptions(
        operation: &Self::Operation,
        exceptions: &ReadTrustExceptions,
    ) -> Result<()>;

    /// Bind the verified artifact to one operation and its decryption key.
    fn into_trusted<'a>(
        artifact: Cow<'a, Self>,
        key_ctx: &'a KeyContext,
        operation: Self::Operation,
        options: OperationOptions,
    ) -> Result<Self::Trusted<'a>>
    where
        Self: 'a;
}
