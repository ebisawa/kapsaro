// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::key::types::KeyExportResult;
use crate::io::keystore::storage::load_public_key;
use crate::Result;
use std::path::PathBuf;

use super::common::{resolve_active_kid, resolve_keystore_root};

pub fn export_key(
    home: Option<PathBuf>,
    member_handle: String,
    kid: Option<String>,
) -> Result<KeyExportResult> {
    let keystore_root = resolve_keystore_root(home)?;
    let kid = resolve_active_kid(&keystore_root, &member_handle, kid)?;
    let public_key = load_public_key(&keystore_root, &member_handle, &kid)?;

    Ok(KeyExportResult {
        member_handle,
        kid,
        public_key,
    })
}
