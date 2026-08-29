// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Decoded shape of a single kv-enc entry token: nonce, ciphertext, and disclosure flag.
//! The disclosed flag is omitted from serialization when false to keep undisclosed entries compact.

use serde::{Deserialize, Serialize};

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KvEntryValue {
    pub nonce: String,
    #[serde(rename = "ct")]
    pub ct: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disclosed: bool,
}
