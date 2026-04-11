// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/verify/key_loader module
//!
//! Tests for embedded signer_pub based verifying key loading.

use crate::test_utils::setup_test_workspace_from_fixtures;
use crate::test_utils::ALICE_MEMBER_ID;
use secretenv::feature::verify::key_loader::load_verifying_key_from_signature;
use secretenv::io::keystore::storage::{list_kids, load_public_key};
use secretenv::model::signature::Signature;
use secretenv::model::verification::VerifyingKeySource;
use std::fs;

use crate::test_utils::setup_test_keystore_from_fixtures;

/// load_verifying_key_from_signature fails with E_SIGNER_PUB_MISSING
/// when signer_pub is not embedded in the signature
#[test]
fn test_load_verifying_key_from_signature_missing_signer_pub_fails() {
    let signature = Signature {
        alg: "eddsa-ed25519".to_string(),
        kid: "SOME_KID_0000000000000000".to_string(),
        signer_pub: None,
        sig: "dummy".to_string(),
    };

    let result = load_verifying_key_from_signature(&signature, false);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("signer_pub is missing"),
        "Expected E_SIGNER_PUB_MISSING error, got: {}",
        err_msg
    );
}

/// load_verifying_key_from_signature extracts key from embedded signer_pub.
#[test]
fn test_load_verifying_key_from_signature_with_signer_pub() {
    let (_temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID]);

    // Read Alice's public key from workspace to get the kid
    let member_file = workspace_dir
        .join("members/active")
        .join(format!("{}.json", ALICE_MEMBER_ID));
    let content = fs::read_to_string(&member_file).unwrap();
    let public_key: secretenv::model::public_key::PublicKey =
        serde_json::from_str(&content).unwrap();
    let kid = public_key.protected.kid.clone();

    let signature = Signature {
        alg: "eddsa-ed25519".to_string(),
        kid: kid.clone(),
        signer_pub: Some(public_key),
        sig: "dummy".to_string(), // sig field not used during key loading
    };

    let loaded = load_verifying_key_from_signature(&signature, false).unwrap();

    assert_eq!(loaded.member_id, ALICE_MEMBER_ID);
    assert_eq!(loaded.source, VerifyingKeySource::SignerPubEmbedded);
    // Verify the key is not zero (sanity check)
    let key_bytes: [u8; 32] = loaded.verifying_key.to_bytes();
    assert_ne!(key_bytes, [0u8; 32]);
    // Verify public_key is populated
    assert_eq!(loaded.public_key.protected.member_id, ALICE_MEMBER_ID);
    assert_eq!(loaded.public_key.protected.kid, kid);
}

/// load_verifying_key_from_signature succeeds even when the signer is not in
/// workspace active members because cryptographic verification is self-contained.
#[test]
fn test_load_verifying_key_from_signature_with_signer_pub_not_active_member_succeeds() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Create a separate empty workspace (not the one setup_test_keystore created)
    let empty_workspace = temp_dir.path().join("empty_workspace");
    fs::create_dir_all(empty_workspace.join("members/active")).unwrap();
    fs::create_dir_all(empty_workspace.join("members/incoming")).unwrap();

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    let signature = Signature {
        alg: "eddsa-ed25519".to_string(),
        kid: kid.clone(),
        signer_pub: Some(public_key),
        sig: "dummy".to_string(),
    };

    let loaded = load_verifying_key_from_signature(&signature, false).unwrap();

    assert_eq!(loaded.member_id, ALICE_MEMBER_ID);
    assert_eq!(loaded.public_key.protected.kid, kid.as_str());
}

/// load_verifying_key_from_signature succeeds without a workspace because
/// embedded signer_pub is the verification source.
#[test]
fn test_load_verifying_key_from_signature_with_signer_pub_no_workspace_succeeds() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    let signature = Signature {
        alg: "eddsa-ed25519".to_string(),
        kid: kid.clone(),
        signer_pub: Some(public_key),
        sig: "dummy".to_string(),
    };

    let loaded = load_verifying_key_from_signature(&signature, false).unwrap();

    assert_eq!(loaded.member_id, ALICE_MEMBER_ID);
    assert_eq!(loaded.public_key.protected.kid, kid.as_str());
}

/// load_verifying_key_from_signature returns error when kid in signature
/// does not match kid in embedded signer_pub
#[test]
fn test_load_verifying_key_from_signature_kid_mismatch() {
    let (_temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID]);

    // Read Alice's public key from workspace
    let member_file = workspace_dir
        .join("members/active")
        .join(format!("{}.json", ALICE_MEMBER_ID));
    let content = fs::read_to_string(&member_file).unwrap();
    let public_key: secretenv::model::public_key::PublicKey =
        serde_json::from_str(&content).unwrap();

    // Create a signature with a different kid than what's in the embedded public key
    let signature = Signature {
        alg: "eddsa-ed25519".to_string(),
        kid: "MISMATCHED_KID_000000000000".to_string(),
        signer_pub: Some(public_key),
        sig: "dummy".to_string(),
    };

    let result = load_verifying_key_from_signature(&signature, false);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("kid mismatch"),
        "Expected kid mismatch error, got: {}",
        err_msg
    );
}
