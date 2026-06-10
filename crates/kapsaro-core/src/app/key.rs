// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for key commands.

use crate::Error;

pub mod export;
pub mod generate;
pub mod github;
pub mod manage;
pub mod timestamp;
pub mod types;

pub(crate) fn build_no_active_key_error(member_handle: &str) -> Error {
    Error::build_not_found_error(format!("No active key for member: {}", member_handle))
}
