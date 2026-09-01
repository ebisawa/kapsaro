// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Strongly typed internal identity values.

use crate::error::{KID_INVALID_RULE, MEMBER_HANDLE_INVALID_RULE};
use crate::support::kid::normalize_kid;
use crate::support::validation::validate_member_handle;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;

/// A syntactically validated member handle.
///
/// This type validates identifier syntax only; it does not establish identity trust.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct MemberHandle(String);

impl MemberHandle {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_member_handle(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for MemberHandle {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for MemberHandle {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl Display for MemberHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for MemberHandle {
    type Error = crate::Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<String> for MemberHandle {
    type Error = crate::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for MemberHandle {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|error| coded_de_error(MEMBER_HANDLE_INVALID_RULE, &error))
    }
}

impl From<MemberHandle> for String {
    fn from(value: MemberHandle) -> Self {
        value.into_string()
    }
}

impl PartialEq<&str> for MemberHandle {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for MemberHandle {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Kid(String);

impl Kid {
    /// Build a `kid` that is already in canonical serialized form.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Self::from_canonical(value)
    }

    /// Build a `kid` from a stored value that must already be canonical.
    ///
    /// Serialized documents carry the canonical form, so accepting display form
    /// here would silently rewrite bytes that a signature was computed over.
    pub(crate) fn from_canonical(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let canonical = normalize_kid(&value).map_err(|_| build_non_canonical_kid_error())?;
        if canonical != value {
            return Err(build_non_canonical_kid_error());
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

fn build_non_canonical_kid_error() -> Error {
    Error::build_invalid_argument_error(
        "kid must be canonical: exactly 32 uppercase Crockford Base32 characters",
    )
}

impl AsRef<str> for Kid {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for Kid {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl Display for Kid {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for Kid {
    type Error = crate::Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<String> for Kid {
    type Error = crate::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

/// Reject a stored `kid` that is not canonical.
///
/// The wire models spell `kid` as a `String`, so nothing in the crate currently
/// deserializes straight into this type: stored documents are validated against
/// their JSON Schema, which pins the canonical shape, and a malformed `kid` is
/// refused there as a schema error. This impl keeps the invariant with the type
/// rather than with the callers, so a future wire model holding a `Kid` cannot
/// arrive at a non-canonical one, and the rule code names the constraint for
/// whoever reads the message.
impl<'de> Deserialize<'de> for Kid {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_canonical(value).map_err(|error| coded_de_error(KID_INVALID_RULE, &error))
    }
}

impl From<Kid> for String {
    fn from(value: Kid) -> Self {
        value.into_string()
    }
}

impl PartialEq<&str> for Kid {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for Kid {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

/// Carry the stable rule code into a serde error, which cannot hold our own
/// error type. The code stays visible to whoever reads the message.
fn coded_de_error<E>(rule: &str, error: &crate::Error) -> E
where
    E: serde::de::Error,
{
    E::custom(format!("{}: {}", rule, error.format_user_message()))
}
