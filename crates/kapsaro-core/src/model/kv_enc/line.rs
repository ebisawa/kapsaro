// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Line-level model of a kv-enc text file: its version marker and each logical line kind.
//! KvEncVersion only accepts the current version 1, so a future bump has one place to extend.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KvEncVersion(u32);

impl KvEncVersion {
    pub const V1: KvEncVersion = KvEncVersion(1);

    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// Read the version as it is spelled on the header line.
    ///
    /// The header line is part of the signed text, so only the canonical
    /// spelling of a version is a valid header. A numerically equal spelling
    /// such as `01` names no version.
    pub fn parse(text: &str) -> Option<Self> {
        (text == "1").then_some(KvEncVersion::V1)
    }
}

impl fmt::Display for KvEncVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvEncLine {
    Header { version: KvEncVersion },
    Head { token: String },
    Wrap { token: String },
    KV { key: String, token: String },
    Sig { token: String },
    Empty,
}
