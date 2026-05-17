// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Error types for the secretenv project.

use std::error::Error as StdError;
use std::fmt;

type BoxedSource = Box<dyn StdError + Send + Sync>;

/// Stable error category exposed to embedding applications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Schema,
    Crypto,
    Ssh,
    Verify,
    Io,
    Parse,
    Config,
    NotFound,
    InvalidArgument,
    InvalidOperation,
}

/// The main error type for secretenv operations.
///
/// The representation is intentionally opaque. Match on [`ErrorKind`] through
/// [`Error::kind`] and use the provided accessors instead of depending on
/// internal storage details.
#[derive(Debug)]
pub struct Error {
    repr: ErrorRepr,
}

#[derive(Debug)]
enum ErrorRepr {
    Schema {
        message: String,
        source: Option<BoxedSource>,
    },
    Crypto {
        message: String,
        source: Option<BoxedSource>,
    },
    Ssh {
        message: String,
        source: Option<BoxedSource>,
    },
    Verify {
        rule: String,
        message: String,
    },
    Io {
        message: String,
        source: Option<std::io::Error>,
    },
    Parse {
        message: String,
        source: Option<BoxedSource>,
    },
    Config {
        message: String,
    },
    NotFound {
        message: String,
    },
    InvalidArgument {
        message: String,
    },
    InvalidOperation {
        message: String,
    },
}

/// A convenient Result type alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Return the stable category for this error.
    pub fn kind(&self) -> ErrorKind {
        match &self.repr {
            ErrorRepr::Schema { .. } => ErrorKind::Schema,
            ErrorRepr::Crypto { .. } => ErrorKind::Crypto,
            ErrorRepr::Ssh { .. } => ErrorKind::Ssh,
            ErrorRepr::Verify { .. } => ErrorKind::Verify,
            ErrorRepr::Io { .. } => ErrorKind::Io,
            ErrorRepr::Parse { .. } => ErrorKind::Parse,
            ErrorRepr::Config { .. } => ErrorKind::Config,
            ErrorRepr::NotFound { .. } => ErrorKind::NotFound,
            ErrorRepr::InvalidArgument { .. } => ErrorKind::InvalidArgument,
            ErrorRepr::InvalidOperation { .. } => ErrorKind::InvalidOperation,
        }
    }

    /// Return the verification rule for verification errors.
    pub fn verification_rule(&self) -> Option<&str> {
        match &self.repr {
            ErrorRepr::Verify { rule, .. } => Some(rule),
            _ => None,
        }
    }

    /// Build a JSON Schema validation error.
    pub fn build_schema_error(message: impl Into<String>) -> Self {
        Self::schema_error_with_boxed_source(message.into(), None)
    }

    /// Build a JSON Schema validation error with a source error.
    pub fn build_schema_error_with_source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::schema_error_with_boxed_source(message.into(), Some(Box::new(source)))
    }

    /// Build a verification error.
    pub fn build_verification_error(rule: impl Into<String>, message: impl Into<String>) -> Self {
        Self::from_repr(ErrorRepr::Verify {
            rule: rule.into(),
            message: message.into(),
        })
    }

    /// Build a parse error.
    pub fn build_parse_error(message: impl Into<String>) -> Self {
        Self::parse_error_with_boxed_source(message.into(), None)
    }

    /// Build a parse error with a source error.
    pub fn build_parse_error_with_source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::parse_error_with_boxed_source(message.into(), Some(Box::new(source)))
    }

    /// Build a configuration error.
    pub fn build_config_error(message: impl Into<String>) -> Self {
        Self::from_repr(ErrorRepr::Config {
            message: message.into(),
        })
    }

    /// Build a not found error.
    pub fn build_not_found_error(message: impl Into<String>) -> Self {
        Self::from_repr(ErrorRepr::NotFound {
            message: message.into(),
        })
    }

    /// Build an invalid argument error.
    pub fn build_invalid_argument_error(message: impl Into<String>) -> Self {
        Self::from_repr(ErrorRepr::InvalidArgument {
            message: message.into(),
        })
    }

    /// Build an invalid operation error.
    pub fn build_invalid_operation_error(message: impl Into<String>) -> Self {
        Self::from_repr(ErrorRepr::InvalidOperation {
            message: message.into(),
        })
    }

    /// Build a cryptographic error.
    pub fn build_crypto_error(message: impl Into<String>) -> Self {
        Self::crypto_error_with_boxed_source(message.into(), None)
    }

    /// Build a cryptographic error with a source error.
    pub fn build_crypto_error_with_source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::crypto_error_with_boxed_source(message.into(), Some(Box::new(source)))
    }

    /// Build an I/O error.
    pub fn build_io_error(message: impl Into<String>) -> Self {
        Self::from_repr(ErrorRepr::Io {
            message: message.into(),
            source: None,
        })
    }

    /// Build an I/O error with a source error.
    pub fn build_io_error_with_source(message: impl Into<String>, source: std::io::Error) -> Self {
        Self::from_repr(ErrorRepr::Io {
            message: message.into(),
            source: Some(source),
        })
    }

    /// Build an SSH error.
    pub fn build_ssh_error(message: impl Into<String>) -> Self {
        Self::ssh_error_with_boxed_source(message.into(), None)
    }

    /// Build an SSH error with a source error.
    pub fn build_ssh_error_with_source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::ssh_error_with_boxed_source(message.into(), Some(Box::new(source)))
    }

    /// Return a concise user-facing message without variant prefix.
    ///
    /// Unlike `Display` (e.g. "Cryptographic error: message"), this returns
    /// only the message body.
    pub fn format_user_message(&self) -> &str {
        match &self.repr {
            ErrorRepr::Schema { message, .. } => message,
            ErrorRepr::Crypto { message, .. }
            | ErrorRepr::Ssh { message, .. }
            | ErrorRepr::Verify { message, .. }
            | ErrorRepr::Io { message, .. }
            | ErrorRepr::Parse { message, .. }
            | ErrorRepr::Config { message }
            | ErrorRepr::NotFound { message }
            | ErrorRepr::InvalidArgument { message }
            | ErrorRepr::InvalidOperation { message } => message,
        }
    }

    pub(crate) fn schema_error_with_boxed_source(
        message: String,
        source: Option<BoxedSource>,
    ) -> Self {
        Self::from_repr(ErrorRepr::Schema { message, source })
    }

    pub(crate) fn crypto_error_with_boxed_source(
        message: String,
        source: Option<BoxedSource>,
    ) -> Self {
        Self::from_repr(ErrorRepr::Crypto { message, source })
    }

    pub(crate) fn ssh_error_with_boxed_source(
        message: String,
        source: Option<BoxedSource>,
    ) -> Self {
        Self::from_repr(ErrorRepr::Ssh { message, source })
    }

    pub(crate) fn parse_error_with_boxed_source(
        message: String,
        source: Option<BoxedSource>,
    ) -> Self {
        Self::from_repr(ErrorRepr::Parse { message, source })
    }

    fn from_repr(repr: ErrorRepr) -> Self {
        Self { repr }
    }

    fn source_ref(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.repr {
            ErrorRepr::Schema { source, .. }
            | ErrorRepr::Crypto { source, .. }
            | ErrorRepr::Ssh { source, .. }
            | ErrorRepr::Parse { source, .. } => source.as_deref().map(|error| error as _),
            ErrorRepr::Io { source, .. } => source.as_ref().map(|error| error as _),
            ErrorRepr::Verify { .. }
            | ErrorRepr::Config { .. }
            | ErrorRepr::NotFound { .. }
            | ErrorRepr::InvalidArgument { .. }
            | ErrorRepr::InvalidOperation { .. } => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.repr {
            ErrorRepr::Schema { message, .. } => write!(formatter, "{message}"),
            ErrorRepr::Crypto { message, .. } => {
                write!(formatter, "Cryptographic error: {message}")
            }
            ErrorRepr::Ssh { message, .. } => write!(formatter, "SSH error: {message}"),
            ErrorRepr::Verify { rule, message } => {
                write!(formatter, "Verification failed [{rule}]: {message}")
            }
            ErrorRepr::Io { message, .. } => write!(formatter, "I/O error: {message}"),
            ErrorRepr::Parse { message, .. } => write!(formatter, "Parse error: {message}"),
            ErrorRepr::Config { message } => write!(formatter, "Configuration error: {message}"),
            ErrorRepr::NotFound { message } => write!(formatter, "Not found: {message}"),
            ErrorRepr::InvalidArgument { message } => {
                write!(formatter, "Invalid argument: {message}")
            }
            ErrorRepr::InvalidOperation { message } => {
                write!(formatter, "Invalid operation: {message}")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source_ref()
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
        Error::build_parse_error_with_source(format!("JSON error: {}", err), err)
    }
}

impl From<crate::crypto::CryptoError> for Error {
    fn from(err: crate::crypto::CryptoError) -> Self {
        match err {
            crate::crypto::CryptoError::InvalidKey { message }
            | crate::crypto::CryptoError::KeyDerivationFailed { message } => {
                Error::build_crypto_error(message)
            }
            crate::crypto::CryptoError::OperationFailed { message, source } => {
                Error::crypto_error_with_boxed_source(message, source)
            }
        }
    }
}

impl From<crate::io::ssh::SshError> for Error {
    fn from(err: crate::io::ssh::SshError) -> Self {
        let crate::io::ssh::SshError::OperationFailed { message, source } = err;
        Error::ssh_error_with_boxed_source(message, source)
    }
}

impl From<crate::format::FormatError> for Error {
    fn from(err: crate::format::FormatError) -> Self {
        Error::build_parse_error(err.to_string())
    }
}

impl From<hkdf::InvalidLength> for Error {
    fn from(_err: hkdf::InvalidLength) -> Self {
        Error::build_crypto_error("HKDF key derivation failed")
    }
}
