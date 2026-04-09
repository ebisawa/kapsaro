// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON output utilities for CLI commands.

use crate::{Error, Result};
use serde::Serialize;

pub(crate) mod key;
pub(crate) mod kv;
pub(crate) mod member;
pub(crate) mod rewrap;
pub(crate) mod trust;

/// Print a serializable value as pretty-printed JSON.
///
/// # Arguments
/// * `value` - The value to serialize and print
///
/// # Returns
/// Result indicating success or failure
pub(crate) fn print_json_output<T: Serialize>(value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value).map_err(|e| Error::Parse {
        message: format!("Failed to serialize JSON: {}", e),
        source: Some(Box::new(e)),
    })?;
    println!("{}", json);
    Ok(())
}
