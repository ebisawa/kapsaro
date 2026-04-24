// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH-specific error types

use thiserror::Error;

/// Error type for SSH operations.
#[derive(Error, Debug)]
pub enum SshError {
    /// SSH operation failed.
    #[error("SSH error: {message}")]
    OperationFailed {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl SshError {
    /// Build an SSH error.
    pub fn build_operation_failed_error(message: impl Into<String>) -> Self {
        SshError::OperationFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Build an SSH error with a source error.
    pub fn build_operation_failed_error_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        SshError::OperationFailed {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}
