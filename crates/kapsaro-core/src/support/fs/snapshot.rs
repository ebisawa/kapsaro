// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::{Error, Result};

use super::read::{load_text, load_text_with_limit};

pub fn ensure_text_file_matches_snapshot(
    path: &Path,
    reviewed_content: Option<&str>,
    subject_display: &str,
) -> Result<()> {
    ensure_text_file_matches_snapshot_impl(path, reviewed_content, subject_display, |path| {
        load_text(path)
    })
}

pub fn ensure_text_file_matches_snapshot_with_limit(
    path: &Path,
    reviewed_content: Option<&str>,
    subject_display: &str,
    max_bytes: usize,
) -> Result<()> {
    ensure_text_file_matches_snapshot_impl(path, reviewed_content, subject_display, |path| {
        load_text_with_limit(path, max_bytes, subject_display)
    })
}

fn ensure_text_file_matches_snapshot_impl<F>(
    path: &Path,
    reviewed_content: Option<&str>,
    subject_display: &str,
    read_current: F,
) -> Result<()>
where
    F: Fn(&Path) -> Result<String>,
{
    match reviewed_content {
        Some(reviewed_content) => {
            let current = read_current(path).map_err(|e| {
                Error::build_invalid_operation_error(format!(
                    "{} changed since review: failed to read current file ({})",
                    subject_display, e
                ))
            })?;
            if current == reviewed_content {
                return Ok(());
            }
        }
        None => {
            if !path.exists() {
                return Ok(());
            }
        }
    }

    Err(Error::build_invalid_operation_error(format!(
        "{} changed since review and must be reviewed again.",
        subject_display
    )))
}
