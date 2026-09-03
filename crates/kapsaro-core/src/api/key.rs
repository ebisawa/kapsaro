// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public local-keystore API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::key::{
    build_missing_member_handle_error, save_private_export_text, validate_environment_key,
    KeyContext, KeyContextOptions, Kid, LocalKeyContextRequest, LocalKeyStore, MemberHandle,
    RecipientKeys,
};

pub mod generate {
    pub use crate::service::key::generate::{
        generate_key_command, KeyExpiryRequest, KeyGenerationHome,
    };
}

pub mod manage {
    pub use crate::service::key::manage::{
        activate_key_command, export_key_command, export_private_key_command, list_keys_command,
        remove_key_command,
    };
}

pub mod types {
    pub use crate::service::key::types::{
        KeyActivateResult, KeyExportPrivateResult, KeyExportResult, KeyGenerationResult, KeyInfo,
        KeyListResult, KeyRemoveResult, MissingKeyDocument,
    };
}
