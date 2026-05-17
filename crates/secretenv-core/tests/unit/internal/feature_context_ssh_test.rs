// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH signing context resolution.

use crate::app::context::ssh::{
    build_ssh_signing_context_with_params, resolve_ssh_key_candidates_with_params, SshSigningParams,
};
use crate::test_utils::setup_test_keystore;
use secretenv_core::cli_api::test_support::domain::ssh::SshDeterminismStatus;
use secretenv_core::cli_api::test_support::settings::types::SshSigningMethod;

#[test]
fn test_resolve_and_build_ssh_signing_context_default() {
    let temp_dir = setup_test_keystore("test@example.com");
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");

    let params = SshSigningParams {
        ssh_key: Some(ssh_key_path),
        signing_method: Some(SshSigningMethod::SshKeygen),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: false,
        check_determinism: true,
    };
    let candidates = resolve_ssh_key_candidates_with_params(&params).unwrap();
    let ctx = build_ssh_signing_context_with_params(&params, &candidates[0].public_key).unwrap();

    assert!(!ctx.public_key.is_empty());
    assert!(!ctx.fingerprint.is_empty());
}

#[test]
fn test_resolve_ssh_key_candidates_with_explicit_key() {
    let temp_dir = setup_test_keystore("test@example.com");
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");

    let params = SshSigningParams {
        ssh_key: Some(ssh_key_path),
        signing_method: Some(SshSigningMethod::SshKeygen),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: false,
        check_determinism: true,
    };

    let candidates = resolve_ssh_key_candidates_with_params(&params).unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(!candidates[0].public_key.is_empty());
    assert!(candidates[0].public_key.starts_with("ssh-ed25519 "));
    assert!(candidates[0].fingerprint.starts_with("SHA256:"));
}

#[test]
fn test_build_ssh_signing_context_from_selected_key() {
    let temp_dir = setup_test_keystore("test@example.com");
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let ssh_pub = ssh_pub.trim();

    let params = SshSigningParams {
        ssh_key: Some(ssh_key_path),
        signing_method: Some(SshSigningMethod::SshKeygen),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: false,
        check_determinism: true,
    };

    let ctx = build_ssh_signing_context_with_params(&params, ssh_pub).unwrap();
    assert_eq!(ctx.public_key, ssh_pub);
    assert!(!ctx.fingerprint.is_empty());
    assert!(ctx.fingerprint.starts_with("SHA256:"));
}

#[test]
fn test_resolve_agent_with_explicit_key_loads_pubkey_from_file() {
    // When ssh-agent mode is selected with an explicit key file,
    // resolve_ssh_key_candidates should load from file, returning 1 candidate.
    let temp_dir = setup_test_keystore("test@example.com");
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");

    let params = SshSigningParams {
        ssh_key: Some(ssh_key_path),
        signing_method: Some(SshSigningMethod::SshAgent),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: false,
        check_determinism: true,
    };

    let candidates = resolve_ssh_key_candidates_with_params(&params).unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].public_key.starts_with("ssh-ed25519 "));

    // Building context may fail without a real agent for determinism check.
    let result = build_ssh_signing_context_with_params(&params, &candidates[0].public_key);
    match result {
        Ok(ctx) => {
            assert!(!ctx.public_key.is_empty());
            assert!(!ctx.fingerprint.is_empty());
        }
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("agent")
                    || msg.contains("ssh_auth_sock")
                    || msg.contains("determinism"),
                "Expected agent/determinism error, got: {}",
                msg
            );
        }
    }
}

#[test]
fn test_resolve_agent_with_explicit_nonexistent_key_fails() {
    // When ssh-agent mode is selected with an explicit key that doesn't exist,
    // resolve_ssh_key_candidates should fail with a NotFound error.
    let temp_dir = setup_test_keystore("test@example.com");
    let nonexistent_key = temp_dir.path().join(".ssh").join("nonexistent_key");

    let params = SshSigningParams {
        ssh_key: Some(nonexistent_key),
        signing_method: Some(SshSigningMethod::SshAgent),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: false,
        check_determinism: true,
    };

    let result = resolve_ssh_key_candidates_with_params(&params);
    let msg = match result {
        Ok(_) => panic!("Expected error for nonexistent key"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("does not exist"),
        "Expected 'does not exist' error, got: {}",
        msg
    );
}

#[test]
fn test_build_ssh_signing_context_skips_determinism_check_when_disabled() {
    let temp_dir = setup_test_keystore("test@example.com");
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let ssh_pub = ssh_pub.trim();

    let params = SshSigningParams {
        ssh_key: Some(ssh_key_path),
        signing_method: Some(SshSigningMethod::SshKeygen),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: false,
        check_determinism: false,
    };

    let ctx = build_ssh_signing_context_with_params(&params, ssh_pub).unwrap();
    assert_eq!(ctx.determinism, SshDeterminismStatus::Skipped);
}

#[test]
fn test_build_ssh_signing_context_checks_determinism_when_enabled() {
    let temp_dir = setup_test_keystore("test@example.com");
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let ssh_pub = ssh_pub.trim();

    let params = SshSigningParams {
        ssh_key: Some(ssh_key_path),
        signing_method: Some(SshSigningMethod::SshKeygen),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: false,
        check_determinism: true,
    };

    let ctx = build_ssh_signing_context_with_params(&params, ssh_pub).unwrap();
    assert_eq!(ctx.determinism, SshDeterminismStatus::Verified);
}
