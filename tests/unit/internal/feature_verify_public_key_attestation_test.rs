// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::ssh::{
    build_ssh_signing_context_with_params, resolve_ssh_key_candidates_with_params, SshSigningParams,
};
use crate::test_utils::generate_temp_ssh_keypair_in_dir;
use secretenv::config::types::SshSigningMethod;
use secretenv::crypto::sign::sign_detached_bytes;
use secretenv::feature::key::generate::{generate_key, KeyGenerationOptions};
use secretenv::feature::verify::public_key::verify_public_key_with_attestation;
use secretenv::format::jcs;
use secretenv::io::keystore::storage::load_public_key;
use secretenv::model::wire::alg;
use secretenv::support::codec::base64_public::decode_base64url_nopad_array;
use serial_test::serial;
use tempfile::TempDir;

fn generate_real_ssh_attested_public_key(
    temp_dir: &TempDir,
) -> secretenv::model::public_key::PublicKey {
    let (ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair_in_dir(temp_dir);
    let home_dir = temp_dir.path().join("home");
    std::fs::create_dir_all(&home_dir).unwrap();

    let params = SshSigningParams {
        ssh_key: Some(ssh_priv),
        signing_method: Some(SshSigningMethod::SshKeygen),
        base_dir: Some(home_dir.clone()),
        verbose: false,
        check_determinism: true,
    };
    let candidates = resolve_ssh_key_candidates_with_params(&params).unwrap();
    let ssh_signing_context =
        build_ssh_signing_context_with_params(&params, &candidates[0].public_key).unwrap();

    let result = generate_key(KeyGenerationOptions {
        member_handle: "attestation-test@example.com".to_string(),
        home: Some(home_dir.clone()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        no_activate: false,
        debug: false,
        github_account: None,
        verbose: false,
        ssh_binding: ssh_signing_context.into_ssh_binding(),
    })
    .unwrap();

    load_public_key(
        &home_dir.join("keys"),
        "attestation-test@example.com",
        &result.kid,
    )
    .unwrap()
}

#[test]
fn generated_public_key_verifies_with_attestation() {
    let temp_dir = TempDir::new().unwrap();
    let public_key = generate_real_ssh_attested_public_key(&temp_dir);
    verify_public_key_with_attestation(&public_key, false).unwrap();
}

#[test]
#[serial]
fn generated_public_key_verifies_with_attestation_repeatedly() {
    for _ in 0..5 {
        let temp_dir = TempDir::new().unwrap();
        let public_key = generate_real_ssh_attested_public_key(&temp_dir);
        verify_public_key_with_attestation(&public_key, false).unwrap();
    }
}

#[test]
fn public_key_with_resigned_but_mismatched_kid_fails_verification() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&temp_dir);
    let (private_key_plaintext, mut public_key) =
        crate::test_utils::keygen_test("attestation-test@example.com", &ssh_priv, &ssh_pub_content)
            .unwrap();

    let signing_key_bytes =
        decode_base64url_nopad_array(&private_key_plaintext.keys.sig.d, "sig.d").unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes);

    public_key.protected.kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string();
    let protected_jcs = jcs::normalize(&public_key.protected).unwrap();
    public_key.signature =
        sign_detached_bytes(&protected_jcs, &signing_key, alg::SIGNATURE_ED25519).unwrap();

    let error = verify_public_key_with_attestation(&public_key, false)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("V-KID-DERIVED") || error.contains("derived kid"),
        "unexpected error: {error}"
    );
}
