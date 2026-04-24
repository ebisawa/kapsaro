// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for CI key export and environment variable key loading.
//!
//! These tests exercise the full portable export -> env var loading pipeline
//! using properly generated key pairs with SSH attestation.

use crate::app::context::crypto::load_crypto_context_from_env;
use secretenv::feature::context::env_key::load_private_key_from_env;
use secretenv::feature::key::portable_export::export_private_key_portable;
use tempfile::TempDir;

use crate::test_utils::{generate_temp_ssh_keypair_in_dir, keygen_test, EnvGuard};

const ENV_PRIVATE_KEY: &str = "SECRETENV_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "SECRETENV_KEY_PASSWORD";

/// Generate a key pair and export it as a portable string.
///
/// Returns (exported_base64url, member_id, kid, plaintext, public_key).
fn generate_and_export(
    member_id: &str,
    password: &str,
) -> (
    String,
    secretenv::model::private_key::PrivateKeyPlaintext,
    secretenv::model::public_key::PublicKey,
) {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&temp_dir);

    let (plaintext, public_key) =
        keygen_test(member_id, &ssh_priv, &ssh_pub_content).expect("keygen should succeed");

    let exported = export_private_key_portable(
        &plaintext,
        &public_key.protected.member_id,
        &public_key.protected.kid,
        public_key
            .protected
            .created_at
            .as_deref()
            .unwrap_or("2026-01-01T00:00:00Z"),
        &public_key.protected.expires_at,
        password,
        false,
    )
    .expect("export should succeed")
    .into_plain_string_for_output();

    (exported, plaintext, public_key)
}

#[test]
fn test_env_key_roundtrip_with_attested_keys() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let member_id = "ci-roundtrip@example.com";
    let password = "strong-test-password-42";

    let (exported, plaintext, public_key) = generate_and_export(member_id, password);

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, password);

    let result = load_private_key_from_env(false).expect("load from env should succeed");

    assert_eq!(result.member_id, member_id);
    assert_eq!(result.verified_key.proof().member_id(), member_id);
    assert_eq!(result.verified_key.proof().kid(), public_key.protected.kid);
    assert!(result.verified_key.proof().ssh_fpr().is_none());

    // Verify key material matches original
    assert_eq!(
        result.verified_key.document().keys.sig.x,
        plaintext.keys.sig.x
    );
    assert_eq!(
        result.verified_key.document().keys.sig.d,
        plaintext.keys.sig.d
    );
    assert_eq!(
        result.verified_key.document().keys.kem.x,
        plaintext.keys.kem.x
    );
    assert_eq!(
        result.verified_key.document().keys.kem.d,
        plaintext.keys.kem.d
    );
}

#[test]
fn test_env_key_wrong_password_error() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let member_id = "wrong-pass@example.com";
    let password = "strong-test-password-42";

    let (exported, _plaintext, _public_key) = generate_and_export(member_id, password);

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, "different-wrong-password");

    let result = load_private_key_from_env(false);
    assert!(result.is_err(), "wrong password should fail");
    assert!(
        std::env::var(ENV_PRIVATE_KEY).is_err(),
        "SECRETENV_PRIVATE_KEY should be cleared after failed load"
    );
    assert!(
        std::env::var(ENV_KEY_PASSWORD).is_err(),
        "SECRETENV_KEY_PASSWORD should be cleared after failed load"
    );
}

#[test]
fn test_env_key_roundtrip_preserves_key_material_for_decryption() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let member_id = "ci-decrypt@example.com";
    let password = "strong-test-password-42";

    let (exported, _plaintext, public_key) = generate_and_export(member_id, password);

    // Load from env
    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, password);

    let env_result = load_private_key_from_env(false).expect("load from env should succeed");

    assert_eq!(env_result.member_id, public_key.protected.member_id);
    assert_eq!(
        env_result.verified_key.proof().kid(),
        public_key.protected.kid
    );
    assert_eq!(
        env_result.verified_key.document().keys.sig.x,
        public_key.protected.identity.keys.sig.x
    );
    assert_eq!(
        env_result.verified_key.document().keys.kem.x,
        public_key.protected.identity.keys.kem.x
    );
}

#[test]
fn test_load_crypto_context_from_env_does_not_require_workspace_member_file() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let password = "strong-test-password-42";
    let (exported, _plaintext, public_key) =
        generate_and_export("ci-no-lookup@example.com", password);

    let workspace = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace.path().join("secrets")).unwrap();

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, password);

    let ctx = load_crypto_context_from_env(workspace.path().to_path_buf(), false)
        .expect("env crypto context should not require own workspace member file");

    assert_eq!(ctx.member_id, public_key.protected.member_id);
    assert_eq!(ctx.kid, public_key.protected.kid);
    assert_eq!(
        ctx.private_key.document().keys.sig.x,
        public_key.protected.identity.keys.sig.x
    );
    assert_eq!(
        ctx.private_key.document().keys.kem.x,
        public_key.protected.identity.keys.kem.x
    );
}
