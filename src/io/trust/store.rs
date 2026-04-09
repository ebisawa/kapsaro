// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store file I/O with atomic writes and permission enforcement.

use crate::model::trust_store::TrustStoreDocument;
use crate::support::fs::{atomic, check_permission_chain, load_text_with_limit};
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::Path;

/// Load result including the document and any permission warnings.
#[derive(Debug)]
pub struct LoadedTrustStore {
    pub document: TrustStoreDocument,
    pub permission_warnings: Vec<String>,
}

/// Load a trust store from disk. Returns `None` if the file does not exist.
pub fn load_trust_store(path: &Path, base_dir: &Path) -> Result<Option<LoadedTrustStore>> {
    if !path.exists() {
        return Ok(None);
    }

    let permission_warnings = check_permission_chain(path, base_dir);
    let content = load_text_with_limit(path, MAX_JSON_DOCUMENT_READ_SIZE, "Trust store")?;
    let document = parse_trust_store(&content, path)?;
    validate_filename_matches_owner(path, &document)?;

    Ok(Some(LoadedTrustStore {
        document,
        permission_warnings,
    }))
}

/// Save a trust store atomically with restricted permissions.
///
/// - Parent directory is created with mode 0700
/// - File is written atomically (write-then-rename)
/// - File permission is set to 0600 on Unix
pub fn save_trust_store(path: &Path, document: &TrustStoreDocument) -> Result<()> {
    atomic::save_json_restricted(path, document)
}

fn parse_trust_store(content: &str, path: &Path) -> Result<TrustStoreDocument> {
    serde_json::from_str(content).map_err(|e| Error::Parse {
        message: format!(
            "Failed to parse trust store {}: {}",
            display_path_relative_to_cwd(path),
            e
        ),
        source: Some(Box::new(e)),
    })
}

/// Validate that file name stem matches protected.owner_member_id (spec §8).
fn validate_filename_matches_owner(path: &Path, document: &TrustStoreDocument) -> Result<()> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();

    if stem != document.protected.owner_member_id {
        return Err(Error::Verify {
            rule: "E_TRUST_STORE_FILENAME_MISMATCH".to_string(),
            message: format!(
                "File name stem '{}' does not match owner_member_id '{}'",
                stem, document.protected.owner_member_id
            ),
        });
    }
    Ok(())
}
