// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer recovery for invalid local trust stores.

use std::path::PathBuf;

use crate::app::context::options::CommonCommandOptions;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct TrustStoreResetPlan {
    pub path: PathBuf,
    pub warning_message: String,
}

#[derive(Debug)]
pub struct TrustStoreResetOutcome {
    pub path: PathBuf,
}

pub fn requires_trust_store_reset(error: &Error) -> bool {
    error.kind() == ErrorKind::Verify
        && error.verification_rule() == Some("E_TRUST_STORE_RESET_REQUIRED")
}

pub fn build_trust_store_reset_plan(
    options: &CommonCommandOptions,
    owner_handle: &str,
    error: Error,
    is_interactive: bool,
) -> Result<TrustStoreResetPlan> {
    if !is_interactive {
        return Err(build_non_interactive_reset_error(error));
    }
    let base_dir = options.resolve_base_dir()?;
    Ok(TrustStoreResetPlan {
        path: get_trust_store_file_path(&base_dir, owner_handle),
        warning_message: error.format_user_message().to_string(),
    })
}

pub fn execute_trust_store_reset(plan: &TrustStoreResetPlan) -> Result<TrustStoreResetOutcome> {
    if !plan.path.exists() {
        return Ok(TrustStoreResetOutcome {
            path: plan.path.clone(),
        });
    }

    std::fs::remove_file(&plan.path).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to remove invalid local trust store {}: {}",
                format_path_relative_to_cwd(&plan.path),
                e
            ),
            e,
        )
    })?;
    Ok(TrustStoreResetOutcome {
        path: plan.path.clone(),
    })
}

fn build_non_interactive_reset_error(error: Error) -> Error {
    Error::build_invalid_operation_error(format!(
        "{} (non-interactive mode cannot confirm trust store reset)",
        error.format_user_message()
    ))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_recovery_test.rs"]
mod tests;
