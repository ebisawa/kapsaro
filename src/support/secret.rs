// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Secret-bearing value types with zeroization on drop.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// Environment variables containing secret values.
pub type SecretEnvMap = BTreeMap<String, SecretString>;

/// UTF-8 secret bytes that must be cleared from memory on drop.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap owned secret bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Take ownership of a `Zeroizing<Vec<u8>>` without cloning.
    pub fn from_zeroizing(mut bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(std::mem::take(&mut *bytes))
    }

    /// Borrow the secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the secret bytes and return the owned buffer.
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("bytes", &"[REDACTED]")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// UTF-8 secret text that must be cleared from memory on drop.
pub struct SecretString(String);

impl SecretString {
    /// Wrap owned secret text.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Take ownership of a `Zeroizing<String>` without cloning.
    pub fn from_zeroizing(mut value: Zeroizing<String>) -> Self {
        Self(std::mem::take(&mut *value))
    }

    /// Borrow the secret text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert the secret text into an `OsString` at a process boundary.
    pub fn into_os_string(mut self) -> OsString {
        OsString::from(std::mem::take(&mut self.0))
    }

    /// Convert the secret text into a plain `String` at an explicit output boundary.
    pub fn into_plain_string_for_output(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretString")
            .field("value", &"[REDACTED]")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl TryFrom<SecretBytes> for SecretString {
    type Error = std::string::FromUtf8Error;

    fn try_from(value: SecretBytes) -> Result<Self, Self::Error> {
        String::from_utf8(value.into_vec()).map(Self::new)
    }
}

impl TryFrom<Zeroizing<Vec<u8>>> for SecretString {
    type Error = std::string::FromUtf8Error;

    fn try_from(value: Zeroizing<Vec<u8>>) -> Result<Self, Self::Error> {
        SecretBytes::from_zeroizing(value).try_into()
    }
}
