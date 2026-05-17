// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Private key protection binding bytes.

use crate::crypto::types::data::Aad;
use crate::format::jcs;
use crate::model::private_key::PrivateKeyProtected;
use crate::Result;

pub fn build_private_key_aad(protected: &PrivateKeyProtected) -> Result<Aad> {
    let value = serde_json::to_value(protected)?;
    let bytes = jcs::normalize_to_bytes(&value)?;
    Ok(Aad::from(bytes))
}
