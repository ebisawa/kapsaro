// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Config bootstrap functionality
//!
//! Provides validation helpers for member_id.

use crate::support::validation;

/// Validate member_id using the common ASCII identifier rules
pub fn validate_member_id(input: &str) -> std::result::Result<(), String> {
    validation::validate_member_id(input).map_err(|e| e.to_string())
}
