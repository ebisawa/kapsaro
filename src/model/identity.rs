// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Strongly typed internal identity values.

use crate::support::kid::normalize_kid;
use crate::support::validation::validate_member_id;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MemberId(String);

impl MemberId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_member_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for MemberId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for MemberId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl Display for MemberId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for MemberId {
    type Error = crate::Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<String> for MemberId {
    type Error = crate::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<MemberId> for String {
    fn from(value: MemberId) -> Self {
        value.into_string()
    }
}

impl PartialEq<&str> for MemberId {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for MemberId {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Kid(String);

impl Kid {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self(normalize_kid(&value.into())?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
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
