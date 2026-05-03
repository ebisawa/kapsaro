// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::keygen_helpers::{build_verified_private_key, build_verified_recipient_key};
use ed25519_dalek::SigningKey;
use secretenv::crypto::kem::{derive_public_key_from_secret, X25519PublicKey, X25519SecretKey};
use secretenv::feature::decrypt::file::decrypt_file_document;
use secretenv::model::file_enc::VerifiedFileEncDocument;
use secretenv::model::verification::{SignatureVerificationProof, VerifyingKeySource};
use secretenv::model::{
    private_key::{IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKeyPlaintext},
    public_key::{
        Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
        VerifiedRecipientKey,
    },
};
use secretenv::support::codec::base64_public::encode_base64url_nopad;

pub(super) fn b64url(data: &[u8]) -> String {
    encode_base64url_nopad(data)
}

pub(super) fn decrypt_file_document_for_test(
    file_enc_doc: &secretenv::model::file_enc::FileEncDocument,
    member_handle: &str,
    kid: &str,
    private_key: &PrivateKeyPlaintext,
    signer_kid: &str,
) -> zeroize::Zeroizing<Vec<u8>> {
    let proof = SignatureVerificationProof::new(
        member_handle.to_string(),
        signer_kid.to_string(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );
    let verified_doc = VerifiedFileEncDocument::new(file_enc_doc.clone(), proof);
    let decrypted_key = build_verified_private_key(private_key, member_handle, kid, "SHA256:test");
    decrypt_file_document(&verified_doc, member_handle, kid, &decrypted_key, false).unwrap()
}

pub(super) fn generate_x25519_keypair(seed: [u8; 32]) -> (X25519SecretKey, X25519PublicKey) {
    let mut clamped = seed;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    let secret = X25519SecretKey::from_bytes(clamped);
    let public = derive_public_key_from_secret(&secret).unwrap();

    (secret, public)
}

pub(super) fn generate_ed25519_keypair(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

pub(super) fn recipients_and_members(
    recipients_with_keys: &[(String, PublicKey)],
) -> (Vec<String>, Vec<VerifiedRecipientKey>) {
    let recipient_handles = recipients_with_keys
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    let members = recipients_with_keys
        .iter()
        .map(|(_, pk)| build_verified_recipient_key(pk.clone()))
        .collect();
    (recipient_handles, members)
}

pub(super) fn build_test_public_key(member_handle: &str, kid: &str, kem_pub: &str) -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: secretenv::model::identifiers::format::PUBLIC_KEY_V5.to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
                        x: kem_pub.to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
                        x: "dummy_sig_pub".to_string(),
                    },
                },
                attestation: Attestation {
                    method: secretenv::io::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN
                        .to_string(),
                    pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE".to_string(),
                    sig: "dummy".to_string(),
                },
            },
            binding_claims: None,
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            created_at: Some("2025-01-01T00:00:00Z".to_string()),
        },
        signature: "dummy".to_string(),
    }
}

pub(super) fn build_test_private_key(
    sk: &X25519SecretKey,
    pk: &X25519PublicKey,
) -> PrivateKeyPlaintext {
    let sk_b64 = b64url(sk.as_bytes());
    let pk_b64 = b64url(pk.as_bytes());

    PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
                x: pk_b64,
                d: sk_b64,
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
                x: "dummy_sig_pub".to_string(),
                d: "dummy_sig_priv".to_string(),
            },
        },
    }
}
