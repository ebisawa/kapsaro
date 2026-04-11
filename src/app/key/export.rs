// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::model::public_key::PublicKey;
use crate::support::fs::atomic;
use crate::{Error, Result};
use std::path::Path;

pub(super) fn save_exported_public_key(out: &Path, public_key: &PublicKey) -> Result<()> {
    let json = serde_json::to_string_pretty(public_key).map_err(|e| Error::Parse {
        message: format!("Failed to serialize public key: {}", e),
        source: Some(Box::new(e)),
    })?;
    atomic::save_text(out, &json)
}
