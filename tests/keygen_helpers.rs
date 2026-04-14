// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation helpers for v3 testing with real SSH attestation and encryption.
//!
//! All test keys are generated with proper SSH attestation (via ssh-keygen) and
//! encrypted with real SSH key protection. No test-only bypasses in production code.

use secretenv::crypto::kem::generate_keypair as generate_kem_material;
use secretenv::feature::key::material::generate_keypairs;
use secretenv::feature::key::protection::encryption::{
    encrypt_private_key, PrivateKeyEncryptionParams,
};
use secretenv::feature::key::public_key_document::{
    build_attestation, build_public_key, PublicKeyBuildParams,
};
use secretenv::feature::key::ssh_binding::SshBindingContext;
use secretenv::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use secretenv::io::ssh::backend::SignatureBackend;
use secretenv::io::ssh::external::keygen::DefaultSshKeygen;
use secretenv::io::ssh::protocol::{build_sha256_fingerprint, SshKeyDescriptor};
use secretenv::model::{
    private_key::{IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyPlaintext},
    public_key::{
        AttestationProof, AttestedIdentity, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey,
        VerifiedPublicKeyAttested, VerifiedRecipientKey,
    },
    ssh::SshDeterminismStatus,
    verification::{ExpiryProof, SelfSignatureProof},
    verified::{DecryptionProof, VerifiedPrivateKey},
};
use secretenv::support::codec::base64_public::{
    decode_base64url_nopad_array, encode_base64url_nopad,
};
use secretenv::support::codec::base64_secret::encode_base64url_nopad_secret_32;
use secretenv::support::secret::SecretArray;
use secretenv::{Error, Result};
use std::path::Path;
use time::OffsetDateTime;

// ============================================================================
// SSH context helpers
// ============================================================================

/// Build an SshBindingContext for tests using a real SSH keypair.
fn build_test_ssh_context(ssh_key_path: &Path, ssh_pubkey: &str) -> Result<SshBindingContext> {
    let fingerprint = build_sha256_fingerprint(ssh_pubkey)?;
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(ssh_key_path.to_path_buf()),
    ));
    Ok(SshBindingContext {
        public_key: ssh_pubkey.to_string(),
        fingerprint,
        backend,
        determinism: SshDeterminismStatus::Verified,
    })
}

// ============================================================================
// Helpers
// ============================================================================

/// Encode bytes to base64url (no padding)
fn b64(data: &[u8]) -> String {
    encode_base64url_nopad(data)
}

// ============================================================================
// Key Pair Generation
// ============================================================================

/// Generate X25519 KEM key pair
fn generate_kem_keypair() -> (JwkOkpPrivateKey, String) {
    let (sk, pk) = generate_kem_material().unwrap();

    let pub_key = b64(pk.as_bytes());
    let keypair = JwkOkpPrivateKey {
        kty: "OKP".to_string(),
        crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
        x: pub_key.clone(),
        d: encode_base64url_nopad_secret_32(&SecretArray::new(*sk.as_bytes()))
            .into_plain_string_for_output(),
    };

    (keypair, pub_key)
}

/// Generate Ed25519 signing key pair
fn generate_sig_keypair() -> (JwkOkpPrivateKey, String) {
    let generated = generate_keypairs().unwrap();
    let sk = generated.sig_sk;
    let pk = generated.sig_pk;

    let pub_key = b64(&pk.to_bytes());
    let keypair = JwkOkpPrivateKey {
        kty: "OKP".to_string(),
        crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
        x: pub_key.clone(),
        d: encode_base64url_nopad_secret_32(&SecretArray::new(sk.to_bytes()))
            .into_plain_string_for_output(),
    };

    (keypair, pub_key)
}

// ============================================================================
// Public API
// ============================================================================

/// Generate a test key pair with real SSH attestation.
///
/// Uses the provided SSH key to create a proper attestation signature.
/// The returned PublicKey passes `verify_public_key_with_attestation()`.
pub fn keygen_test(
    member_id: &str,
    ssh_key_path: &Path,
    ssh_pubkey: &str,
) -> Result<(PrivateKeyPlaintext, PublicKey)> {
    let (kem_keypair, kem_pub) = generate_kem_keypair();
    let (sig_keypair, sig_pub) = generate_sig_keypair();

    let now = OffsetDateTime::now_utc();
    let created_at = secretenv::support::time::build_timestamp_display(now)?;
    let expires_at =
        secretenv::support::time::build_timestamp_display(now + time::Duration::days(365))?;

    // Extract signing key from keypair before moving it
    let sig_key_bytes =
        decode_base64url_nopad_array(&sig_keypair.d, "signing key").map_err(|e| Error::Crypto {
            message: format!("Failed to decode signing key: {}", e),
            source: None,
        })?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sig_key_bytes);

    let private_key = PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: kem_keypair,
            sig: sig_keypair,
        },
    };

    let identity_keys = IdentityKeys {
        kem: JwkOkpPublicKey {
            kty: "OKP".to_string(),
            crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
            x: kem_pub,
        },
        sig: JwkOkpPublicKey {
            kty: "OKP".to_string(),
            crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
            x: sig_pub,
        },
    };

    // Build real SSH attestation
    let ssh_context = build_test_ssh_context(ssh_key_path, ssh_pubkey)?;
    let attestation = build_attestation(&ssh_context, &identity_keys)?;

    let identity = Identity {
        keys: identity_keys,
        attestation,
    };
    let public_key = build_public_key(&PublicKeyBuildParams {
        member_id,
        identity,
        created_at: &created_at,
        expires_at: &expires_at,
        sig_sk: &signing_key,
        debug: false,
        github_account: None,
    })?;

    Ok((private_key, public_key))
}

/// Create a test PrivateKey with real SSH key encryption.
///
/// Uses `encrypt_private_key()` with the provided SSH key to produce
/// a properly encrypted PrivateKey document.
pub fn create_test_private_key(
    plaintext: &PrivateKeyPlaintext,
    member_id: &str,
    kid: &str,
    ssh_key_path: &Path,
    ssh_pubkey: &str,
) -> Result<PrivateKey> {
    let ssh_fpr = build_sha256_fingerprint(ssh_pubkey)?;
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(ssh_key_path.to_path_buf()),
    ));

    let now = OffsetDateTime::now_utc();
    let created_at = secretenv::support::time::build_timestamp_display(now)?;
    let expires_at =
        secretenv::support::time::build_timestamp_display(now + time::Duration::days(365))?;

    encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext,
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        backend: backend.as_ref(),
        ssh_pubkey,
        ssh_fpr,
        created_at,
        expires_at,
        debug: false,
    })
}

/// Create a Decrypted wrapper for PrivateKeyPlaintext (for testing only)
///
/// This function wraps a PrivateKeyPlaintext in a VerifiedPrivateKey type without
/// performing full validation. It's intended for test code only.
pub fn make_decrypted_private_key_plaintext(
    plaintext: &PrivateKeyPlaintext,
    member_id: &str,
    kid: &str,
    ssh_fpr: &str,
) -> VerifiedPrivateKey {
    let proof = DecryptionProof::new(
        member_id.to_string(),
        kid.to_string(),
        Some(ssh_fpr.to_string()),
    );
    VerifiedPrivateKey::new(clone_private_key_plaintext_for_test(plaintext), proof)
}

fn clone_private_key_plaintext_for_test(plaintext: &PrivateKeyPlaintext) -> PrivateKeyPlaintext {
    PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: plaintext.keys.kem.kty.clone(),
                crv: plaintext.keys.kem.crv.clone(),
                x: plaintext.keys.kem.x.clone(),
                d: plaintext.keys.kem.d.clone(),
            },
            sig: JwkOkpPrivateKey {
                kty: plaintext.keys.sig.kty.clone(),
                crv: plaintext.keys.sig.crv.clone(),
                x: plaintext.keys.sig.x.clone(),
                d: plaintext.keys.sig.d.clone(),
            },
        },
    }
}

/// Convert a slice of PublicKeys to VerifiedRecipientKey (for testing only).
///
/// Used by tests that call encrypt_kv_document or similar with a list of keys.
pub fn make_verified_members(members: &[PublicKey]) -> Vec<VerifiedRecipientKey> {
    members
        .iter()
        .map(|pk| make_recipient_key(pk.clone()))
        .collect()
}

/// Build a VerifiedRecipientKey wrapper for PublicKey (for testing only).
///
/// This function wraps a PublicKey in a VerifiedRecipientKey type without
/// performing full verification. It's intended for test code only.
pub fn make_recipient_key(public_key: PublicKey) -> VerifiedRecipientKey {
    let attested = make_attested_public_key(public_key);
    VerifiedRecipientKey::new(attested, ExpiryProof::new())
}

/// Build a VerifiedPublicKeyAttested wrapper for PublicKey (for testing only).
pub fn make_attested_public_key(public_key: PublicKey) -> VerifiedPublicKeyAttested {
    let proof = AttestationProof {
        method: public_key.protected.identity.attestation.method.clone(),
        ssh_pub: public_key.protected.identity.attestation.pub_.clone(),
        verified_at: None,
    };
    let attested_identity = AttestedIdentity::new(public_key.protected.identity.clone(), proof);
    let self_sig_proof = SelfSignatureProof::new();
    VerifiedPublicKeyAttested::new(public_key, self_sig_proof, attested_identity)
}

/// Build a dummy PublicKey for tests that only need the structural shape.
///
/// Uses placeholder values for all fields. Not suitable for cryptographic
/// verification — use `keygen_test()` when real key material is needed.
pub fn make_dummy_public_key(kid: &str) -> PublicKey {
    use secretenv::model::public_key::{Attestation, PublicKeyProtected};

    PublicKey {
        protected: PublicKeyProtected {
            format: "secretenv.public.key@4".to_string(),
            member_id: "signer@test".to_string(),
            kid: kid.to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "X25519".to_string(),
                        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "Ed25519".to_string(),
                        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    },
                },
                attestation: Attestation {
                    method: "ssh-sign".to_string(),
                    pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    sig: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ".to_string(),
                },
            },
            binding_claims: None,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    }
}
