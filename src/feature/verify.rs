// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verify feature - signature verification.

pub mod file;
pub mod kv;
pub mod private_key;
pub mod public_key;
pub mod recipients;

pub mod key_loader;
pub(crate) mod report;
pub(crate) mod signature;

use crate::model::public_key::PublicKey;
use crate::model::verification::VerifyingKeySource;

/// Report of signature verification result
#[derive(Debug, Clone)]
pub struct SignatureVerificationReport {
    /// Whether verification succeeded
    pub verified: bool,
    /// Signer's member_handle (if successfully identified)
    pub signer_handle: Option<String>,
    /// Source of the verifying key
    pub source: Option<VerifyingKeySource>,
    /// Warnings (e.g., expired key)
    pub warnings: Vec<String>,
    /// Human-readable message (success or failure reason)
    pub message: String,
    /// Signer's PublicKey (available when verification succeeds)
    pub signer_public_key: Option<PublicKey>,
}
