// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public file-enc artifact API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::file::{
    load_plaintext_bytes, save_decrypted_bytes, save_encrypted_text, FileEncArtifact,
    FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact,
};

pub mod encrypt {
    pub use crate::service::file::encrypt::{
        execute_encrypt_file_command_with_recipient_set_confirmation, resolve_encrypt_file_command,
        EncryptFileCommand,
    };
}
