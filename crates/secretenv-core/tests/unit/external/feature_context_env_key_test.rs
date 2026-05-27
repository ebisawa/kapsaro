// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv_core::cli_api::test_support::domain::private_key::{
    PrivateKey, PrivateKeyAlgorithm, PrivateKeyEncData, PrivateKeyPlaintext, PrivateKeyProtected,
};
use secretenv_core::cli_api::test_support::domain::wire::format;
use secretenv_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;
use secretenv_core::cli_api::test_support::helpers::secret::SecretString;
use secretenv_core::cli_api::test_support::operations::context::env_key::{
    is_env_key_mode, load_private_key_from_env,
};
use secretenv_core::cli_api::test_support::operations::key::material::{
    build_private_key_plaintext, generate_keypairs,
};
use secretenv_core::cli_api::test_support::operations::key::portable_export::{
    export_private_key_portable, ExportPasswordPolicy, PortableExportOptions,
};

use crate::test_utils::EnvGuard;

const ENV_PRIVATE_KEY: &str = "SECRETENV_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "SECRETENV_KEY_PASSWORD";
const TEST_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

fn build_test_plaintext() -> PrivateKeyPlaintext {
    let keypairs = generate_keypairs().unwrap();
    build_private_key_plaintext(
        &keypairs.kem_sk,
        &keypairs.kem_pk,
        &keypairs.sig_sk,
        &keypairs.sig_pk,
    )
}

fn build_exported_key(plaintext: &PrivateKeyPlaintext, password: &str) -> String {
    let password = SecretString::new(password.to_string());
    export_private_key_portable(
        plaintext,
        "alice@example.com",
        TEST_KID,
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &password,
        PortableExportOptions::new(ExportPasswordPolicy::Recommended, false),
    )
    .expect("export should succeed")
    .into_plain_string_for_output()
}

fn assert_env_key_vars_cleared() {
    assert!(
        std::env::var(ENV_PRIVATE_KEY).is_err(),
        "SECRETENV_PRIVATE_KEY should be cleared"
    );
    assert!(
        std::env::var(ENV_KEY_PASSWORD).is_err(),
        "SECRETENV_KEY_PASSWORD should be cleared"
    );
}

#[test]
fn test_is_env_key_mode_when_set() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    std::env::set_var(ENV_PRIVATE_KEY, "dummy-value");

    assert!(is_env_key_mode());
}

#[test]
fn test_is_env_key_mode_when_unset() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    std::env::remove_var(ENV_PRIVATE_KEY);

    assert!(!is_env_key_mode());
}

#[test]
fn test_decode_env_private_key() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let plaintext = build_test_plaintext();
    let password = "strong-password-42-xx";
    let exported = build_exported_key(&plaintext, password);

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, password);

    let result = load_private_key_from_env(false).expect("should succeed");
    assert_eq!(result.member_handle, "alice@example.com");
    assert_eq!(result.verified_key.proof().kid(), TEST_KID);
    assert!(result.verified_key.proof().ssh_fpr().is_none());
    assert_eq!(
        result.verified_key.document().keys.sig.x,
        plaintext.keys.sig.x
    );
    assert_eq!(
        result.verified_key.document().keys.kem.x,
        plaintext.keys.kem.x
    );
}

#[test]
fn test_env_key_missing_password_error() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let plaintext = build_test_plaintext();
    let exported = build_exported_key(&plaintext, "strong-password-42-xx");

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::remove_var(ENV_KEY_PASSWORD);

    let result = load_private_key_from_env(false);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("SECRETENV_KEY_PASSWORD"),
        "error should mention SECRETENV_KEY_PASSWORD: {}",
        err
    );
}

#[test]
fn test_env_key_invalid_base64_error() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    std::env::set_var(ENV_PRIVATE_KEY, "not-valid-base64!!!");
    std::env::set_var(ENV_KEY_PASSWORD, "strong-password-42-xx");

    let result = load_private_key_from_env(false);
    assert!(result.is_err());
    assert_env_key_vars_cleared();
}

#[test]
fn test_env_vars_cleared_after_successful_load() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let plaintext = build_test_plaintext();
    let password = "strong-password-42-xx";
    let exported = build_exported_key(&plaintext, password);

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, password);

    let _result = load_private_key_from_env(false).expect("should succeed");

    assert_env_key_vars_cleared();
}

#[test]
fn test_env_key_rejects_invalid_format() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);

    // Build a PrivateKey with wrong format string
    let bad_format_key = PrivateKey {
        protected: PrivateKeyProtected {
            format: "secretenv.private.key@2".to_string(),
            subject_handle: "alice@example.com".to_string(),
            kid: TEST_KID.to_string(),
            alg: PrivateKeyAlgorithm::Argon2id {
                ikm_salt: encode_base64url_nopad(&[0u8; 32]),
                hkdf_salt: encode_base64url_nopad(&[1u8; 32]),
                aead: "xchacha20-poly1305".to_string(),
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
        },
        encrypted: PrivateKeyEncData {
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ct: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        },
    };

    let json = serde_json::to_vec(&bad_format_key).expect("serialize");
    let encoded = encode_base64url_nopad(&json);

    std::env::set_var(ENV_PRIVATE_KEY, &encoded);
    std::env::set_var(ENV_KEY_PASSWORD, "test-password");

    let result = load_private_key_from_env(false);
    assert!(result.is_err(), "Wrong format should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unsupported document format"),
        "error should mention unsupported document format: {}",
        err
    );
    assert!(!err.contains("Schema validation error"));
    assert_env_key_vars_cleared();
}

#[test]
fn test_env_key_rejects_sshsig_algorithm() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);

    // Build a PrivateKey with SshSig algorithm and encode it
    let sshsig_key = PrivateKey {
        protected: PrivateKeyProtected {
            format: format::PRIVATE_KEY_V7.to_string(),
            subject_handle: "alice@example.com".to_string(),
            kid: TEST_KID.to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "SHA256:dummy".to_string(),
                ikm_salt: encode_base64url_nopad(&[0u8; 32]),
                hkdf_salt: encode_base64url_nopad(&[1u8; 32]),
                aead: "xchacha20-poly1305".to_string(),
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
        },
        encrypted: PrivateKeyEncData {
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ct: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        },
    };

    let json = serde_json::to_vec(&sshsig_key).expect("serialize");
    let encoded = encode_base64url_nopad(&json);

    std::env::set_var(ENV_PRIVATE_KEY, &encoded);
    std::env::set_var(ENV_KEY_PASSWORD, "test-password");

    let result = load_private_key_from_env(false);
    assert!(result.is_err(), "SshSig key should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("password-protected") || err.contains("argon2id"),
        "error should mention password-protected requirement: {}",
        err
    );
    assert_env_key_vars_cleared();
}
