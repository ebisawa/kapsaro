// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::common::{RemovedRecipient, WrapItem};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KvHeader {
    pub sid: Uuid,
    pub alg: KvFileAlgorithm,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KvFileAlgorithm {
    pub aead: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KvWrap {
    pub wrap: Vec<WrapItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_recipients: Option<Vec<RemovedRecipient>>,
}
