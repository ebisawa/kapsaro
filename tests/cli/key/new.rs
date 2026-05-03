// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key new` command

use crate::cli::common::{cmd, generate_temp_ssh_keypair, TEST_MEMBER_HANDLE};
use crate::cli::key::find_kid_in_member_dir;
use predicates::prelude::*;
use secretenv::io::ssh::protocol::constants as ssh_constants;
use secretenv::model::identifiers::{alg, format};
use secretenv::model::{private_key::PrivateKey, public_key::PublicKey};
use secretenv::support::codec::base64_public::decode_base64url_nopad;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_key_new_requires_member_handle_before_ssh_resolution() {
    let temp_dir = TempDir::new().unwrap();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--valid-for")
        .arg("1d")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("member handle not configured")
                .and(predicate::str::contains("SSH key").not())
                .and(predicate::str::contains("GitHub username").not()),
        );
}

#[test]
fn test_key_new_generates_private_key() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Get keystore root
    let keystore_root = temp_dir.path().join("keys");

    // Find the generated kid directory
    let member_dir = keystore_root.join(member_handle);
    assert!(
        member_dir.exists(),
        "Member directory should be created: {}",
        member_dir.display()
    );

    // Find the generated kid
    let kid = find_kid_in_member_dir(&member_dir);

    // Verify private.json exists
    let private_key_path = member_dir.join(&kid).join("private.json");
    assert!(
        private_key_path.exists(),
        "private.json should exist at: {}",
        private_key_path.display()
    );

    // Parse private.json as PrivateKey
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey =
        serde_json::from_str(&private_json).expect("Should parse as PrivateKey");

    // Verify fields
    assert_eq!(
        private_key.protected.format,
        format::PRIVATE_KEY_V6,
        "Format should be secretenv.private.key@6"
    );
    assert_eq!(
        private_key.protected.subject_handle, member_handle,
        "member_handle should match"
    );
    assert_eq!(
        private_key.protected.kid, kid,
        "kid should match directory name"
    );
    assert!(
        !private_key.protected.created_at.is_empty(),
        "created_at should be set"
    );
    assert!(
        !private_key.protected.expires_at.is_empty(),
        "expires_at should be set"
    );

    // Keep temp directories alive until test ends
    drop(ssh_temp);
}

#[test]
fn test_key_new_ssh_protection() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Read private.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey = serde_json::from_str(&private_json).unwrap();

    // Verify alg field via pattern matching
    match &private_key.protected.alg {
        secretenv::model::private_key::PrivateKeyAlgorithm::SshSig {
            fpr,
            ikm_salt,
            hkdf_salt,
            aead,
        } => {
            assert!(
                fpr.starts_with("SHA256:"),
                "protected.alg.fpr should start with SHA256:"
            );
            assert_eq!(
                fpr.len(),
                50,
                "protected.alg.fpr should be 50 characters (SHA256: + 43 chars)"
            );
            let ikm_salt_decoded = decode_base64url_nopad(ikm_salt, "ikm_salt")
                .expect("ikm_salt should be valid base64url");
            assert_eq!(
                ikm_salt_decoded.len(),
                32,
                "ikm_salt should be 32 bytes when decoded"
            );

            let hkdf_salt_decoded = decode_base64url_nopad(hkdf_salt, "hkdf_salt")
                .expect("hkdf_salt should be valid base64url");
            assert_eq!(
                hkdf_salt_decoded.len(),
                32,
                "hkdf_salt should be 32 bytes when decoded"
            );

            assert_eq!(
                aead,
                alg::AEAD_XCHACHA20_POLY1305,
                "protected.alg.aead should be xchacha20-poly1305"
            );
        }
        _ => panic!("Expected SshSig algorithm variant"),
    }
    assert!(
        !private_key.encrypted.nonce.is_empty(),
        "encrypted.nonce should be set"
    );
    assert!(
        !private_key.encrypted.ct.is_empty(),
        "encrypted.ct should be set"
    );

    // Verify nonce is base64url encoded (24 bytes = 32 chars without padding)
    let nonce_decoded = decode_base64url_nopad(&private_key.encrypted.nonce, "nonce")
        .expect("nonce should be valid base64url");
    assert_eq!(
        nonce_decoded.len(),
        24,
        "nonce should be 24 bytes when decoded"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_generates_attestation() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command (explicitly use ssh-keygen to ensure the specified -i key is used)
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--ssh-keygen")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Read public.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let public_key_path = member_dir.join(&kid).join("public.json");
    assert!(
        public_key_path.exists(),
        "public.json should exist at: {}",
        public_key_path.display()
    );

    // Parse public.json as PublicKey
    let public_json = fs::read_to_string(&public_key_path).unwrap();
    let public_key: PublicKey =
        serde_json::from_str(&public_json).expect("Should parse as PublicKey");

    // Verify attestation field
    assert_eq!(
        public_key.protected.identity.attestation.method,
        ssh_constants::ATTESTATION_METHOD_SSH_SIGN,
        "attestation.method should be ssh-sign"
    );

    // Verify attestation.pub contains the SSH public key
    let ssh_pub_normalized = ssh_pub_content.trim();
    assert!(
        ssh_pub_normalized.starts_with(ssh_constants::KEY_TYPE_ED25519),
        "SSH public key should start with ssh-ed25519"
    );
    assert_eq!(
        public_key.protected.identity.attestation.pub_, ssh_pub_normalized,
        "attestation.pub should match SSH public key"
    );

    // Verify sig is set
    assert!(
        !public_key.protected.identity.attestation.sig.is_empty(),
        "attestation.sig should be set"
    );

    // Verify sig is base64url encoded
    decode_base64url_nopad(
        &public_key.protected.identity.attestation.sig,
        "attestation.sig",
    )
    .expect("attestation.sig should be valid base64url");

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_generates_self_sig() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Read public.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let public_key_path = member_dir.join(&kid).join("public.json");
    let public_json = fs::read_to_string(&public_key_path).unwrap();
    let public_key: PublicKey = serde_json::from_str(&public_json).unwrap();

    // Verify self_sig is set
    assert!(!public_key.signature.is_empty(), "self_sig should be set");

    // Verify self_sig is base64url encoded
    let self_sig_decoded = decode_base64url_nopad(&public_key.signature, "self_sig")
        .expect("self_sig should be valid base64url");

    // Ed25519 signature should be 64 bytes
    assert_eq!(
        self_sig_decoded.len(),
        64,
        "self_sig should be 64 bytes (Ed25519 signature) when decoded"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_expires_at_option() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;
    let expires_at = "2027-12-31T23:59:59Z";

    // Run key new command with --expires-at
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--expires-at")
        .arg(expires_at)
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Read private.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey = serde_json::from_str(&private_json).unwrap();

    // Verify expires_at
    assert_eq!(
        private_key.protected.expires_at, expires_at,
        "expires_at should match the specified date"
    );

    // Verify it can be parsed as RFC3339
    time::OffsetDateTime::parse(
        &private_key.protected.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("expires_at should be valid RFC3339");

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_valid_for_1y() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command with --valid-for 1y
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--valid-for")
        .arg("1y")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Read private.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey = serde_json::from_str(&private_json).unwrap();

    // Parse expires_at
    let expires_at = time::OffsetDateTime::parse(
        &private_key.protected.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("expires_at should be valid RFC3339");

    let now = time::OffsetDateTime::now_utc();
    let one_year_later = now + time::Duration::days(365);

    // Verify expires_at is approximately 1 year from now (within 1 minute tolerance)
    let diff = (expires_at - one_year_later).abs();
    assert!(
        diff < time::Duration::minutes(1),
        "expires_at should be approximately 1 year from now"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_valid_for_6m() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command with --valid-for 6m
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--valid-for")
        .arg("6m")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Read private.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey = serde_json::from_str(&private_json).unwrap();

    // Parse expires_at
    let expires_at = time::OffsetDateTime::parse(
        &private_key.protected.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("expires_at should be valid RFC3339");

    let now = time::OffsetDateTime::now_utc();
    let six_months_later = now + time::Duration::days(6 * 30);

    // Verify expires_at is approximately 6 months from now (within 1 minute tolerance)
    let diff = (expires_at - six_months_later).abs();
    assert!(
        diff < time::Duration::minutes(1),
        "expires_at should be approximately 6 months from now"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_valid_for_30d() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command with --valid-for 30d
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--valid-for")
        .arg("30d")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Read private.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey = serde_json::from_str(&private_json).unwrap();

    // Parse expires_at
    let expires_at = time::OffsetDateTime::parse(
        &private_key.protected.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("expires_at should be valid RFC3339");

    let now = time::OffsetDateTime::now_utc();
    let thirty_days_later = now + time::Duration::days(30);

    // Verify expires_at is approximately 30 days from now (within 1 minute tolerance)
    let diff = (expires_at - thirty_days_later).abs();
    assert!(
        diff < time::Duration::minutes(1),
        "expires_at should be approximately 30 days from now"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_no_activate_option() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command with --no-activate
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--no-activate")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify key was created
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    assert!(private_key_path.exists(), "private.json should be created");

    // Verify active file is NOT created
    let active_path = member_dir.join("active");
    assert!(
        !active_path.exists(),
        "active file should NOT be created with --no-activate"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_default_activate() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command without --no-activate
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Get the generated kid
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    // Verify active file is created
    use secretenv::io::keystore::active::load_active_kid;
    let active_kid = load_active_kid(member_handle, &keystore_root).expect("Should get active kid");
    assert_eq!(
        active_kid,
        Some(kid),
        "Active kid should match the generated kid"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}
