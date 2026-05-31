// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for Ed25519DirectBackend

use crate::test_utils::ed25519_backend::Ed25519DirectBackend;
use crate::test_utils::generate_temp_ssh_keypair_in_dir;
use kapsaro_core::cli_api::test_support::storage::ssh::backend::ssh_keygen::SshKeygenBackend;
use kapsaro_core::cli_api::test_support::storage::ssh::backend::SignatureBackend;
use kapsaro_core::cli_api::test_support::storage::ssh::external::keygen::DefaultSshKeygen;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::constants::KEY_PROTECTION_NAMESPACE;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::key_descriptor::SshKeyDescriptor;
use tempfile::TempDir;

#[test]
fn test_ed25519_direct_backend_produces_same_signature_as_ssh_keygen() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&temp_dir);

    let direct = Ed25519DirectBackend::new(&ssh_priv).unwrap();
    let keygen = SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(ssh_priv),
    );

    let challenge = b"test challenge for compatibility";

    let sig_direct = direct
        .sign_sshsig(KEY_PROTECTION_NAMESPACE, &ssh_pub_content, challenge)
        .unwrap();
    let sig_keygen = keygen
        .sign_sshsig(KEY_PROTECTION_NAMESPACE, &ssh_pub_content, challenge)
        .unwrap();

    assert_eq!(
        sig_direct.as_bytes(),
        sig_keygen.as_bytes(),
        "Ed25519DirectBackend must produce identical signatures to SshKeygenBackend"
    );
}

#[test]
fn test_ed25519_direct_backend_is_deterministic() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&temp_dir);

    let backend = Ed25519DirectBackend::new(&ssh_priv).unwrap();
    let challenge = b"determinism test";

    // sign_sshsig_deterministic calls sign_sshsig twice and checks equality
    let result =
        backend.sign_sshsig_deterministic(KEY_PROTECTION_NAMESPACE, &ssh_pub_content, challenge);
    assert!(result.is_ok(), "Ed25519 signing must be deterministic");
}

#[test]
fn test_ed25519_direct_backend_different_challenges_produce_different_sigs() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&temp_dir);

    let backend = Ed25519DirectBackend::new(&ssh_priv).unwrap();

    let sig1 = backend
        .sign_sshsig(KEY_PROTECTION_NAMESPACE, &ssh_pub_content, b"challenge A")
        .unwrap();
    let sig2 = backend
        .sign_sshsig(KEY_PROTECTION_NAMESPACE, &ssh_pub_content, b"challenge B")
        .unwrap();

    assert_ne!(
        sig1.as_bytes(),
        sig2.as_bytes(),
        "Different challenges must produce different signatures"
    );
}
