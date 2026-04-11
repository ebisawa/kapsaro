// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::keystore::active::load_active_kid;
use crate::io::keystore::helpers::resolve_member_kid_query;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

pub(crate) fn resolve_keystore_root(home: Option<PathBuf>) -> Result<PathBuf> {
    KeystoreResolver::resolve(home.as_ref())
}

pub(crate) fn resolve_active_kid(
    keystore_root: &Path,
    member_id: &str,
    kid: Option<String>,
) -> Result<String> {
    match kid {
        Some(kid) => resolve_member_kid_query(keystore_root, member_id, &kid),
        None => load_active_kid(member_id, keystore_root)?.ok_or_else(|| Error::NotFound {
            message: format!("No active key for member: {}", member_id),
        }),
    }
}
