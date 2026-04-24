// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Error types for the secretenv project.

use thiserror::Error;

/// The main error type for secretenv operations.
#[derive(Error, Debug)]
pub enum Error {
    /// JSON Schema validation failed.
    #[error("Schema validation error: {message}")]
    Schema {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Cryptographic operation failed (HPKE, Ed25519, etc.).
    #[error("Cryptographic error: {message}")]
    Crypto {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// SSH-related error (ssh-agent, SSHSIG verification, fingerprint parsing).
    #[error("SSH error: {message}")]
    Ssh {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Verification rule violation.
    #[error("Verification failed [{rule}]: {message}")]
    Verify { rule: String, message: String },

    /// File I/O error.
    #[error("I/O error: {message}")]
    Io {
        message: String,
        #[source]
        source: Option<std::io::Error>,
    },

    /// Parsing error (JSON, base64, etc.).
    #[error("Parse error: {message}")]
    Parse {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Configuration error (missing config, invalid settings).
    #[error("Configuration error: {message}")]
    Config { message: String },

    /// Resource not found (key, member, workspace, file, etc.).
    #[error("Not found: {message}")]
    NotFound { message: String },

    /// Invalid argument or validation failure.
    #[error("Invalid argument: {message}")]
    InvalidArgument { message: String },

    /// Invalid operation error (e.g., attempting to sign with a public key).
    #[error("Invalid operation: {message}")]
    InvalidOperation { message: String },
}

/// A convenient Result type alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Build a verification error.
    pub fn build_verification_error(rule: impl Into<String>, message: impl Into<String>) -> Self {
        Error::Verify {
            rule: rule.into(),
            message: message.into(),
        }
    }

    /// Build a parse error.
    pub fn build_parse_error(message: impl Into<String>) -> Self {
        Error::Parse {
            message: message.into(),
            source: None,
        }
    }

    /// Build a parse error with a source error.
    pub fn build_parse_error_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Error::Parse {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Build a configuration error.
    pub fn build_config_error(message: impl Into<String>) -> Self {
        Error::Config {
            message: message.into(),
        }
    }

    /// Build a not found error.
    pub fn build_not_found_error(message: impl Into<String>) -> Self {
        Error::NotFound {
            message: message.into(),
        }
    }

    /// Build an invalid argument error.
    pub fn build_invalid_argument_error(message: impl Into<String>) -> Self {
        Error::InvalidArgument {
            message: message.into(),
        }
    }

    /// Build an invalid operation error.
    pub fn build_invalid_operation_error(message: impl Into<String>) -> Self {
        Error::InvalidOperation {
            message: message.into(),
        }
    }

    /// Build a cryptographic error.
    pub fn build_crypto_error(message: impl Into<String>) -> Self {
        Error::Crypto {
            message: message.into(),
            source: None,
        }
    }

    /// Build a cryptographic error with a source error.
    pub fn build_crypto_error_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Error::Crypto {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Build an I/O error.
    pub fn build_io_error(message: impl Into<String>) -> Self {
        Error::Io {
            message: message.into(),
            source: None,
        }
    }

    /// Build an I/O error with a source error.
    pub fn build_io_error_with_source(message: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            message: message.into(),
            source: Some(source),
        }
    }

    /// Build an SSH error with a source error.
    pub fn build_ssh_error_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Error::Ssh {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Return a concise user-facing message without variant prefix.
    ///
    /// Unlike `Display` (e.g. "Cryptographic error: message"), this returns
    /// only the message body. For `Schema`, the potentially large instance
    /// data is replaced with a fixed description.
    pub fn format_user_message(&self) -> &str {
        match self {
            Error::Schema { .. } => "Schema validation failed",
            Error::Crypto { message, .. }
            | Error::Ssh { message, .. }
            | Error::Verify { message, .. }
            | Error::Io { message, .. }
            | Error::Parse { message, .. }
            | Error::Config { message }
            | Error::NotFound { message }
            | Error::InvalidArgument { message }
            | Error::InvalidOperation { message } => message,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        let message = err.to_string();
        Error::build_io_error_with_source(message, err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Parse {
            message: format!("JSON error: {}", err),
            source: Some(Box::new(err)),
        }
    }
}

impl From<crate::crypto::CryptoError> for Error {
    fn from(err: crate::crypto::CryptoError) -> Self {
        match err {
            crate::crypto::CryptoError::InvalidKey { message } => Error::Crypto {
                message,
                source: None,
            },
            crate::crypto::CryptoError::OperationFailed { message, source } => {
                Error::Crypto { message, source }
            }
            crate::crypto::CryptoError::KeyDerivationFailed { message } => Error::Crypto {
                message,
                source: None,
            },
        }
    }
}

impl From<crate::io::ssh::SshError> for Error {
    fn from(err: crate::io::ssh::SshError) -> Self {
        let crate::io::ssh::SshError::OperationFailed { message, source } = err;
        Error::Ssh { message, source }
    }
}

impl From<crate::format::FormatError> for Error {
    fn from(err: crate::format::FormatError) -> Self {
        Error::Parse {
            message: err.to_string(),
            source: None,
        }
    }
}

impl From<hkdf::InvalidLength> for Error {
    fn from(_err: hkdf::InvalidLength) -> Self {
        Error::build_crypto_error("HKDF key derivation failed")
    }
}
