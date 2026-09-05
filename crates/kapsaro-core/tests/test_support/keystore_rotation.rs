// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore rotation helpers for service-layer tests.
//! Adds further keys to a fixture keystore so a test can exercise key rotation.
//!
//! These helpers build key pairs and write them into the keystore directly,
//! rather than through the production `key new` command path. Any invariant
//! that path enforces — attestation on the generated public key, the active
//! marker staying consistent with what is on disk — is therefore something
//! this module has to reproduce by hand rather than something it gets for
//! free. When the production path grows a new invariant, keeping this module
//! honest about it is on whoever changes that path, not something checked
//! automatically here.

use std::fs;
use std::path::Path;

use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::{Kid, MemberHandle};
use crate::test_utils::{build_test_private_key, keygen_test};

/// Generate one more key pair for a member and store it without activating it.
pub(crate) fn add_generated_key(home: &Path, member_handle: &str) -> Kid {
    let ssh_public_key = fs::read_to_string(home.join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_private_key = home.join(".ssh/test_ed25519");
    let (private_plaintext, public_key) =
        keygen_test(member_handle, &ssh_private_key, &ssh_public_key).unwrap();
    let kid = Kid::try_from(public_key.protected.kid.as_str()).unwrap();
    let private_key = build_test_private_key(
        &private_plaintext,
        member_handle,
        kid.as_str(),
        &ssh_private_key,
        &ssh_public_key,
    )
    .unwrap();
    let access = KeystoreAccess::open(home.join("keys")).unwrap();
    let member = MemberHandle::try_from(member_handle).unwrap();
    access
        .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
        .unwrap();
    kid
}

/// Generate one more key pair for a member and make it the active key.
pub(crate) fn rotate_active_key(home: &Path, member_handle: &str) -> Kid {
    let kid = add_generated_key(home, member_handle);
    let access = KeystoreAccess::open(home.join("keys")).unwrap();
    let member = MemberHandle::try_from(member_handle).unwrap();
    access.activate_existing_key(&member, &kid).unwrap();
    kid
}
