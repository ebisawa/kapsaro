// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File artifact operations shared by API callers.

mod core;

pub use core::{
    load_plaintext_bytes, save_decrypted_bytes, save_encrypted_text, FileEncArtifact,
    FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact,
};

pub mod encrypt;
