// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Error types for the kapsaro project.

use std::error::Error as StdError;
use std::fmt;

// Recovery codes. Each names what would let the operator get past a failure,
// and each is independent of what the failure was: a path that cannot be
// trusted is repaired the same way whether reading it parsed badly or never
// got that far. They travel on `Error::recovery`, never as a rule.
pub(crate) const LOCAL_STATE_PATH_UNSAFE_RECOVERY: &str = "E_LOCAL_STATE_PATH_UNSAFE";

/// A stored private key that group or other can reach, refused rather than
/// read. Kept apart from the permission warning and from the unsafe path: the
/// warning says an entry should be repaired and lets the command finish, and an
/// unsafe path is about what stands where local state belongs. This one is the
/// single case where local state permissions stop a read, and the repair for it
/// is one `chmod`.
pub(crate) const LOCAL_STATE_PRIVATE_KEY_EXPOSED_RECOVERY: &str =
    "E_LOCAL_STATE_PRIVATE_KEY_EXPOSED";
pub(crate) const TRUST_SIGNER_KEY_MISSING_RECOVERY: &str = "E_TRUST_SIGNER_KEY_MISSING";
pub(crate) const LOCAL_KEYSTORE_MISSING_RECOVERY: &str = "E_LOCAL_KEYSTORE_MISSING";
pub(crate) const TRUST_STORE_RESET_REQUIRED_RECOVERY: &str = "E_TRUST_STORE_RESET_REQUIRED";

/// A key that still signs the local trust store and cannot be replaced as its
/// signer, so removing it would leave the stored approvals unverifiable.
pub(crate) const TRUST_SIGNER_KEY_IN_USE_RECOVERY: &str = "E_TRUST_SIGNER_KEY_IN_USE";
pub(crate) const MEMBER_HANDLE_REQUIRED_RECOVERY: &str = "E_MEMBER_HANDLE_REQUIRED";

// Codes carried in a serde error message, which cannot hold our own error type.
pub(crate) const MEMBER_HANDLE_INVALID_RULE: &str = "E_MEMBER_HANDLE_INVALID";
pub(crate) const KID_INVALID_RULE: &str = "E_KID_INVALID";

// Diagnostic codes. Reported on a check the diagnostic command emits, never on
// an `Error`.
pub(crate) const LOCAL_STATE_PERMISSIONS_RULE: &str = "W_LOCAL_STATE_PERMISSIONS";

/// An ancestor of local state owned by neither the operator nor the machine
/// administrator. Reported by the diagnostic command only.
pub(crate) const LOCAL_STATE_ANCESTOR_OWNER_RULE: &str = "W_LOCAL_STATE_ANCESTOR_OWNER";

/// An entry an interrupted write staged and never published. Reported by the
/// diagnostic command while normal readers ignore internal staging names.
pub(crate) const LOCAL_STATE_WRITE_RESIDUE_RULE: &str = "W_LOCAL_STATE_WRITE_RESIDUE";

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

impl ErrorKind {
    /// Whether the failure is a statement about the loaded content itself.
    ///
    /// Parsing, schema validation, and signature verification all read the
    /// stored bytes, so a failure of theirs proves the content is unusable. An
    /// I/O failure or an unsafe path says nothing about the content, so it
    /// keeps travelling as itself.
    ///
    /// `InvalidArgument` belongs here for the same reason: the identity values
    /// a stored document carries are parsed back into their types on the way
    /// out, so a handle or a kid that fails validation is a corrupt document
    /// rather than a bad call. Judge this alongside [`Error::kind`] at the call
    /// site when the argument could have come from the caller instead.
    pub(crate) fn is_content_failure(self) -> bool {
        matches!(
            self,
            Self::Schema | Self::Crypto | Self::Verify | Self::Parse | Self::InvalidArgument
        )
    }
}

/// The main error type for kapsaro operations.
///
/// An error answers three questions that do not follow from one another, and
/// each has its own accessor: what went wrong ([`Error::kind`]), which rule the
/// check was made against ([`Error::rule`]), and what would let the operator
/// get past it ([`Error::recovery`]). The last one is orthogonal to the first:
/// a path that cannot be trusted is repaired the same way whether reading it
/// parsed badly or never got that far, so attaching a recovery route never
/// costs the caller the category the failure came in as.
///
/// The representation is intentionally opaque. Match on [`ErrorKind`] through
/// [`Error::kind`] and use the provided accessors instead of depending on
/// internal storage details.
#[derive(Debug)]
pub struct Error {
    repr: ErrorRepr,
    recovery: Option<&'static str>,
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
        rule: Option<String>,
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

/// Turn "it is not there" into absence, leaving every other failure alone.
///
/// Only the not-found category becomes `None`: collapsing an unsafe path or an
/// I/O failure into absence would let a caller carry on as though it had looked
/// and found nothing.
pub(crate) fn absent_as_none<T>(opened: Result<T>) -> Result<Option<T>> {
    match opened {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

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

    /// The validation rule this error was refused under, if there was one.
    ///
    /// Verification and coded configuration failures may name a rule. What
    /// would repair the failure is a separate axis and is read from
    /// [`Error::recovery`] instead, so a rule and a recovery code never have to
    /// be told apart by their name.
    pub fn rule(&self) -> Option<&str> {
        match &self.repr {
            ErrorRepr::Verify { rule, .. } => Some(rule),
            ErrorRepr::Config { rule, .. } => rule.as_deref(),
            _ => None,
        }
    }

    /// The stable code naming what would let the operator get past this error.
    ///
    /// Independent of [`Error::kind`]: any category of failure may have a known
    /// route out of it, and attaching one never changes what the failure was.
    pub fn recovery(&self) -> Option<&'static str> {
        self.recovery
    }

    /// Name the route out of this failure, keeping everything else about it.
    pub(crate) fn with_recovery(mut self, code: &'static str) -> Self {
        self.recovery = Some(code);
        self
    }

    /// Restate this failure with a fuller message, keeping everything else.
    ///
    /// The category, the rule, the recovery route, and the source all decide
    /// how a failure is handled further up, so only the message grows.
    pub(crate) fn with_message(mut self, message: impl Into<String>) -> Self {
        let slot = match &mut self.repr {
            ErrorRepr::Schema { message, .. }
            | ErrorRepr::Crypto { message, .. }
            | ErrorRepr::Ssh { message, .. }
            | ErrorRepr::Verify { message, .. }
            | ErrorRepr::Io { message, .. }
            | ErrorRepr::Parse { message, .. }
            | ErrorRepr::Config { message, .. }
            | ErrorRepr::NotFound { message }
            | ErrorRepr::InvalidArgument { message }
            | ErrorRepr::InvalidOperation { message } => message,
        };
        *slot = message.into();
        self
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

    pub(crate) fn build_json_serialization_error(
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::build_parse_error_with_source(
            format!("JSON serialization failed: {}", source),
            source,
        )
    }

    /// Build a configuration error.
    pub fn build_config_error(message: impl Into<String>) -> Self {
        Self::from_repr(ErrorRepr::Config {
            rule: None,
            message: message.into(),
        })
    }

    /// Build a configuration error associated with a stable validation rule.
    pub fn build_config_error_with_rule(
        rule: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::from_repr(ErrorRepr::Config {
            rule: Some(rule.into()),
            message: message.into(),
        })
    }

    pub(crate) fn build_home_environment_not_set_error() -> Self {
        Self::build_config_error("HOME environment variable not set")
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

    pub(crate) fn build_invalid_sid_error(sid: &str, source: impl fmt::Display) -> Self {
        Self::build_invalid_argument_error(format!("Invalid sid '{}': {}", sid, source))
    }

    /// Build an invalid operation error.
    pub fn build_invalid_operation_error(message: impl Into<String>) -> Self {
        Self::from_repr(ErrorRepr::InvalidOperation {
            message: message.into(),
        })
    }

    /// Refuse local state that is not what the layout expects: an entry of the
    /// wrong file type, a name that cannot be stored, an unpublished staging
    /// entry, or a path that cannot be tied to the object it was checked as.
    pub(crate) fn build_local_state_path_unsafe_error(message: impl Into<String>) -> Self {
        Self::build_invalid_operation_error(message).with_recovery(LOCAL_STATE_PATH_UNSAFE_RECOVERY)
    }

    /// Refuse a stored private key another account can reach.
    ///
    /// The entry is exactly what the layout expects, so this is not an unsafe
    /// path; what stops the read is its mode or its owner. Naming that on its
    /// own lets a caller offer the `chmod` that repairs it without having to
    /// re-inspect the file to find out which condition it met.
    pub(crate) fn build_local_state_private_key_exposed_error(message: impl Into<String>) -> Self {
        Self::build_invalid_operation_error(message)
            .with_recovery(LOCAL_STATE_PRIVATE_KEY_EXPOSED_RECOVERY)
    }

    pub(crate) fn build_local_keystore_missing_error(message: impl Into<String>) -> Self {
        Self::build_invalid_operation_error(message).with_recovery(LOCAL_KEYSTORE_MISSING_RECOVERY)
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
            | ErrorRepr::Config { message, .. }
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
        Self {
            repr,
            recovery: None,
        }
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
            ErrorRepr::Config { message, .. } => {
                write!(formatter, "Configuration error: {message}")
            }
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

#[cfg(test)]
#[path = "../tests/unit/internal/error_display_test.rs"]
mod error_display_test;

#[cfg(test)]
#[path = "../tests/unit/internal/error_test.rs"]
mod error_test;
