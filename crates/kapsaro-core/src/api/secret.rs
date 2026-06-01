// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Secret-bearing facade helper types.

use std::fmt;

use zeroize::Zeroizing;

/// Secret bytes returned through the external facade.
pub struct SecretBytes(crate::support::secret::SecretBytes);

/// Secret UTF-8 text returned through the external facade.
pub struct SecretString(crate::support::secret::SecretString);

impl SecretBytes {
    /// Wrap owned secret bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(crate::support::secret::SecretBytes::new(bytes))
    }

    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(crate::support::secret::SecretBytes::from_zeroizing(bytes))
    }

    /// Explicitly borrow the secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Take ownership as a zeroizing byte buffer.
    pub fn into_zeroizing_vec(self) -> Zeroizing<Vec<u8>> {
        self.0.into_zeroizing_vec()
    }
}

impl SecretString {
    /// Wrap owned secret text.
    pub fn new(value: String) -> Self {
        Self(crate::support::secret::SecretString::new(value))
    }

    /// Take ownership of zeroizing secret text without cloning.
    pub fn from_zeroizing(value: Zeroizing<String>) -> Self {
        Self(crate::support::secret::SecretString::from_zeroizing(value))
    }

    pub(crate) fn from_inner(value: crate::support::secret::SecretString) -> Self {
        Self(value)
    }

    pub(crate) fn as_inner(&self) -> &crate::support::secret::SecretString {
        &self.0
    }

    pub(crate) fn into_inner(self) -> crate::support::secret::SecretString {
        self.0
    }

    /// Explicitly borrow the secret text.
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    /// Convert the secret text into a plain `String` at an explicit output boundary.
    pub fn into_plain_string_for_output(self) -> String {
        self.0.into_plain_string_for_output()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("bytes", &"[REDACTED]")
            .field("len", &self.expose_secret().len())
            .finish()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretString")
            .field("value", &"[REDACTED]")
            .field("len", &self.expose_secret().len())
            .finish()
    }
}
