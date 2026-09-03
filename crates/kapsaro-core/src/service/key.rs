// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local key operations shared by API callers.

use crate::error::MEMBER_HANDLE_REQUIRED_RECOVERY;
use crate::Error;

mod core;

pub use core::{
    save_private_export_text, validate_environment_key, KeyContext, KeyContextOptions, Kid,
    LocalKeyContextRequest, LocalKeyStore, MemberHandle, RecipientKeys,
};

pub mod export;
pub mod generate;
pub mod github;
pub mod manage;
pub mod timestamp;
pub(crate) mod trust_signer;
pub mod types;

pub(crate) fn build_no_active_key_error(member_handle: &str) -> Error {
    Error::build_not_found_error(format!("No active key for member: {}", member_handle))
}

/// Build the domain error used when a caller did not select a member.
pub fn build_missing_member_handle_error(message: impl Into<String>) -> Error {
    Error::build_config_error(message.into()).with_recovery(MEMBER_HANDLE_REQUIRED_RECOVERY)
}
