// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Synthetic key documents for keystore tests.
//! Builds both halves of a key pair whose identity and validity a test chooses.

use crate::model::private_key::{
    PrivateKey, PrivateKeyAlgorithm, PrivateKeyEncData, PrivateKeyProtected,
};
use crate::model::public_key::{
    Attestation, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
};

const B64URL_24: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B64URL_32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Signature placeholder telling one built public key from another.
pub(crate) const TEST_KEY_SIGNATURE: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
pub(crate) const OTHER_TEST_KEY_SIGNATURE: &str =
    "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub(crate) const TEST_KEY_CREATED_AT: &str = "2024-01-01T00:00:00Z";
pub(crate) const TEST_KEY_EXPIRES_AT: &str = "2125-01-01T00:00:00Z";

/// Build the private half of a key pair stating `member_handle` and `kid`.
///
/// The encrypted material is a placeholder: the keystore reading paths parse
/// the document and check what it states about itself without ever unwrapping
/// the key, so a test that is about storage does not need a real one.
pub(crate) fn build_test_private_key_document(member_handle: &str, kid: &str) -> PrivateKey {
    PrivateKey {
        protected: PrivateKeyProtected {
            format: crate::model::wire::format::PRIVATE_KEY_V1.to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "SHA256:TEST123".to_string(),
                ikm_salt: B64URL_32.to_string(),
                hkdf_salt: B64URL_32.to_string(),
                aead: crate::model::wire::algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
            },
            created_at: TEST_KEY_CREATED_AT.to_string(),
            expires_at: TEST_KEY_EXPIRES_AT.to_string(),
        },
        encrypted: PrivateKeyEncData {
            nonce: B64URL_24.to_string(),
            ct: "Y3Q".to_string(),
        },
    }
}

/// Build the public half of a key pair stating `member_handle` and `kid`.
///
/// The caller reaches into `protected` to vary the timestamps, which is what
/// the selection tests are about.
pub(crate) fn build_test_public_key_document(
    member_handle: &str,
    kid: &str,
    signature: &str,
) -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: crate::model::wire::format::PUBLIC_KEY_V1.to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
            keys: IdentityKeys {
                kem: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: crate::model::wire::jwk::CURVE_X25519.to_string(),
                    x: B64URL_32.to_string(),
                },
                sig: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: crate::model::wire::jwk::CURVE_ED25519.to_string(),
                    x: B64URL_32.to_string(),
                },
            },
            attestation: Attestation {
                method: crate::io::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN
                    .to_string(),
                pub_: "ssh-ed25519 AAAA...".to_string(),
                sig: TEST_KEY_SIGNATURE.to_string(),
            },
            binding_claims: None,
            expires_at: TEST_KEY_EXPIRES_AT.to_string(),
            created_at: Some(TEST_KEY_CREATED_AT.to_string()),
        },
        signature: signature.to_string(),
    }
}
