// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

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
