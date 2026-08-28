// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! App-layer opening of the local keystore.
//! Reports a keystore that was never created as the step that creates one.

use std::path::Path;

use crate::io::keystore::access::KeystoreAccess;
use crate::support::fs::anchor::AnchoredDir;
use crate::{Error, ErrorKind, Result};

/// Open the local keystore held under one local state root.
///
/// An absent keystore means no key has been generated yet, so every command
/// that needs one gets the step that fixes it instead of the path that happened
/// to be missing.
pub(crate) fn open_local_keystore(base_dir: &Path) -> Result<KeystoreAccess> {
    KeystoreAccess::open_from_home(base_dir).map_err(map_absent_keystore)
}

/// Open the local keystore under a local state root the caller already holds.
///
/// A command that resolved its paths opened that root once; resolving the name a
/// second time would let a home repointed mid-command hand the keys of another
/// tree to the same command. A root that is not there at all is the same
/// condition as a keystore that is not there.
pub(crate) fn open_local_keystore_at(home: Option<&AnchoredDir>) -> Result<KeystoreAccess> {
    let Some(home) = home else {
        return Err(build_empty_keystore_error());
    };
    KeystoreAccess::open_from_anchored_home(home).map_err(map_absent_keystore)
}

fn map_absent_keystore(error: Error) -> Error {
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
