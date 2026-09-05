// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Service-layer opening of the local keystore.
//! Reports a keystore that was never created as the step that creates one.

use std::path::Path;

use crate::io::keystore::access::KeystoreAccess;
use crate::{Error, ErrorKind, Result};

/// Open the local keystore held under one local state root.
///
/// An absent keystore means no key has been generated yet, so every command
/// that needs one gets the step that fixes it instead of the path that happened
/// to be missing.
pub(crate) fn open_local_keystore(base_dir: &Path) -> Result<KeystoreAccess> {
    KeystoreAccess::open_from_home(base_dir).map_err(build_absent_keystore_error)
}

fn build_absent_keystore_error(error: Error) -> Error {
    if error.kind() == ErrorKind::NotFound {
        return build_empty_keystore_error();
    }
    error
}

fn build_empty_keystore_error() -> Error {
    Error::build_not_found_error(
        "No keys found. Run 'kapsaro key new' to generate a key.".to_string(),
    )
}
