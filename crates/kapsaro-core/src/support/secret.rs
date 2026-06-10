// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Secret-bearing value types with zeroization on drop.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// Environment variables containing secret values.
pub type SecretEnvironmentMap = BTreeMap<String, SecretString>;

/// Fixed-size secret bytes that must be cleared from memory on drop.
pub struct SecretArray<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> SecretArray<N> {
    /// Wrap fixed-size secret bytes.
    pub fn new(bytes: [u8; N]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Take ownership of a zeroizing fixed-size secret buffer without cloning.
    pub fn from_zeroizing(bytes: Zeroizing<[u8; N]>) -> Self {
        Self(bytes)
    }

    /// Explicitly expose the secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn len(&self) -> usize {
        N
    }

    pub fn is_empty(&self) -> bool {
        N == 0
    }

    pub(crate) fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    pub(crate) fn into_zeroizing(self) -> Zeroizing<[u8; N]> {
        self.0
    }
}

impl<const N: usize> fmt::Debug for SecretArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretArray")
            .field("bytes", &"[REDACTED]")
            .field("len", &N)
            .finish()
    }
}

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

    /// Take ownership as a zeroizing byte buffer.
    pub fn into_zeroizing_vec(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut self.0))
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

    fn take_plain_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }

    /// Convert secret text into a plain `String` at an explicit output boundary.
    #[cfg(any(feature = "cli-test-support", test))]
    pub fn into_plain_string_for_output(self) -> String {
        self.take_plain_string()
    }

    /// Convert secret text into a plain `String` at an explicit output boundary.
    #[cfg(not(any(feature = "cli-test-support", test)))]
    pub(crate) fn into_plain_string_for_output(self) -> String {
        self.take_plain_string()
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for SecretString {}

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
        let mut bytes = value.into_zeroizing_vec();
        String::from_utf8(std::mem::take(&mut *bytes)).map(Self::new)
    }
}

impl TryFrom<Zeroizing<Vec<u8>>> for SecretString {
    type Error = std::string::FromUtf8Error;

    fn try_from(value: Zeroizing<Vec<u8>>) -> Result<Self, Self::Error> {
        SecretBytes::from_zeroizing(value).try_into()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_secret_test.rs"]
mod support_secret_test;
