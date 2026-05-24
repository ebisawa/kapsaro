// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KvEncVersion(u32);

impl KvEncVersion {
    pub const V9: KvEncVersion = KvEncVersion(9);

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        (value == 9).then_some(KvEncVersion::V9)
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
