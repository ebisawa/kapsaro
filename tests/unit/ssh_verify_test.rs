// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH signature verification
//!
//! Tests for verify_sshsig validation logic

use secretenv::io::ssh::external::traits::SshKeygen;
use secretenv::io::ssh::protocol::types::Ed25519RawSignature;
use secretenv::io::ssh::verify::verify_sshsig;
use std::path::Path;

const VALID_SIG: &str = "-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----";
const ED25519_KEY: &str = "ssh-ed25519 AAAA... comment";

/// Stub SshKeygen that always succeeds (validation tests never reach trait methods)
struct StubSshKeygen;

impl SshKeygen for StubSshKeygen {
    fn derive_public_key(&self, _key_path: &Path) -> secretenv::Result<String> {
        unimplemented!()
    }
    fn sign(
        &self,
        _key_path: &Path,
        _namespace: &str,
        _data: &[u8],
    ) -> secretenv::Result<Ed25519RawSignature> {
        unimplemented!()
    }
    fn verify(
        &self,
        _ssh_pubkey: &str,
        _namespace: &str,
        _message: &[u8],
        _signature: &str,
    ) -> secretenv::Result<()> {
        Ok(())
    }
}

#[test]
fn test_verify_sshsig_validation() {
    let keygen = StubSshKeygen;

    assert!(verify_sshsig(&keygen, "", b"msg", VALID_SIG)
        .unwrap_err()
        .to_string()
        .contains("empty"));

    assert!(verify_sshsig(&keygen, "ssh-rsa AAAA...", b"msg", VALID_SIG)
        .unwrap_err()
        .to_string()
        .contains(secretenv::io::ssh::protocol::constants::KEY_TYPE_ED25519));

    assert!(verify_sshsig(&keygen, ED25519_KEY, b"msg", "")
        .unwrap_err()
        .to_string()
        .contains("empty"));

    assert!(verify_sshsig(&keygen, ED25519_KEY, b"msg", "invalid")
        .unwrap_err()
        .to_string()
        .contains("armored"));
}
