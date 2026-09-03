// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Shared CryptoContext builder for tests.
// Uses Ed25519DirectBackend to avoid spawning ssh-keygen subprocesses.

use super::ed25519_backend::Ed25519DirectBackend;
use kapsaro_core::test_support::operations::context::crypto::{
    load_crypto_context_from_keystore, CryptoContext,
};
use std::path::Path;

use tempfile::TempDir;

/// Build CryptoContext for a member in a test keystore
///
/// Uses Ed25519DirectBackend instead of SshKeygenBackend to avoid
/// spawning ssh-keygen subprocesses.
pub fn setup_member_key_context(
    temp_dir: &TempDir,
    member_handle: &str,
    explicit_kid: Option<&str>,
) -> CryptoContext {
    setup_member_key_context_at(temp_dir.path(), member_handle, explicit_kid)
}

pub fn setup_member_key_context_at(
    home: &Path,
    member_handle: &str,
    explicit_kid: Option<&str>,
) -> CryptoContext {
    let keystore_root = home.join("keys");
    let ssh_pub = std::fs::read_to_string(home.join(".ssh").join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = home.join(".ssh").join("test_ed25519");
    let backend = Ed25519DirectBackend::new(&ssh_priv).unwrap();

    load_crypto_context_from_keystore(
        keystore_root,
        member_handle,
        explicit_kid,
        Box::new(backend),
        ssh_pub,
        Some(home.join("workspace")),
    )
    .unwrap()
}
