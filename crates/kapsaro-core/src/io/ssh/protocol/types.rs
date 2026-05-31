// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH signature type safety
//!
//! Provides type-safe wrappers for different SSH signature formats to prevent
//! confusion between raw Ed25519 signatures, SSH signature blobs, and SSHSIG blobs.

mod blob;
mod signature;

pub use blob::{SshSignatureBlob, SshsigBlob};
pub use signature::Ed25519RawSignature;
