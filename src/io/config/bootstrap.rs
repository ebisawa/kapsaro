// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Config bootstrap functionality
//!
//! Provides validation helpers for member_handle.

use crate::support::validation;

/// Validate member_handle using the common ASCII identifier rules
pub fn validate_member_handle(input: &str) -> std::result::Result<(), String> {
    validation::validate_member_handle(input).map_err(|e| e.to_string())
}
