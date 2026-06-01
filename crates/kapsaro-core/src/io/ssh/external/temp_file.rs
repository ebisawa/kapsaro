// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Temporary file creation utilities

use crate::{Error, Result};
use std::io::Write;
use tempfile::NamedTempFile;

/// Save bytes to a temporary file
pub fn save_temp_bytes(content: &[u8]) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to create temp file: {}", e), e)
    })?;
    file.write_all(content).map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to write temp file: {}", e), e)
    })?;
    file.flush().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to flush temp file: {}", e), e)
    })?;
    Ok(file)
}

/// Save string to a temporary file
pub fn save_temp_str(content: &str) -> Result<NamedTempFile> {
    save_temp_bytes(content.as_bytes())
}
