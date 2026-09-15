// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File artifact operations shared by API callers.

mod core;
mod input;
pub use input::FileInputTarget;
pub(crate) mod output;
pub use output::FileOutputTarget;

pub use core::{
    load_plaintext_bytes, save_decrypted_bytes, save_encrypted_text, FileEncArtifact,
    FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact,
};

pub mod encrypt;
