// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local key operations shared by API callers.

use crate::error::MEMBER_HANDLE_REQUIRED_RECOVERY;
use crate::Error;

mod core;

pub use crate::support::kid::{format_kid_display, format_kid_display_lossy};
pub use crate::support::time::parse_relative_duration_days;
pub use crate::support::validation::validate_github_login;
pub use core::{
    load_environment_key, save_private_export_text, KeyContext, KeyContextOptions, Kid,
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
