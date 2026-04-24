// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::format::schema::validator::load_embedded_validator;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::{Error, Result};

pub(super) fn validate_kv_document_schema(head: &KvHeader, wrap: &KvWrap) -> Result<()> {
    let validator = load_embedded_validator()?;
    let head_value = serialize_schema_value("HEAD", head)?;
    validator.validate_kv_value(&head_value)?;

    let wrap_value = serialize_schema_value("WRAP", wrap)?;
    validator.validate_kv_file_wrap(&wrap_value)
}

fn serialize_schema_value(label: &str, value: impl serde::Serialize) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| Error::Parse {
        message: format!("Failed to serialize {} for schema validation: {}", label, e),
        source: Some(Box::new(e)),
    })
}
