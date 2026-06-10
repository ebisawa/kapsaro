// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for Verified document types

use crate::model::file_enc::FileEncDocument;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::verification::{SignatureVerificationProof, VerifyingKeySource};
use crate::test_utils::keygen_helpers::{build_dummy_key_possession_proof, build_dummy_public_key};

#[test]
fn test_verified_new() {
    let file_enc_doc = FileEncDocument {
        protected: crate::model::file_enc::FileEncDocumentProtected {
            format: "kapsaro:format:file-enc@1".to_string(),
            sid: uuid::Uuid::new_v4(),
            wrap: vec![],
            removed_recipients: None,
            payload: crate::model::file_enc::FilePayload {
                protected: crate::model::file_enc::FilePayloadHeader {
                    format: "kapsaro:format:file-enc:payload@1".to_string(),
                    sid: uuid::Uuid::new_v4(),
                    alg: crate::model::file_enc::FileEncAlgorithm {
                        aead: "xchacha20-poly1305".to_string(),
                    },
                },
                encrypted: crate::model::file_enc::FilePayloadCiphertext {
                    nonce: "test".to_string(),
                    ct: "test".to_string(),
                },
            },
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        },
        signature: crate::model::signature::ArtifactSignature {
            alg: "eddsa-ed25519".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            mac: build_dummy_key_possession_proof(),
            sig: "test".to_string(),
        },
    };

    let proof = SignatureVerificationProof::new(
        "alice".to_string(),
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );

    let verified = VerifiedFileEncDocument::new(file_enc_doc.clone(), proof.clone());

    assert_eq!(verified.document(), &file_enc_doc);
    assert_eq!(verified.proof(), &proof);
}

#[test]
fn test_verified_into_inner() {
    let file_enc_doc = FileEncDocument {
        protected: crate::model::file_enc::FileEncDocumentProtected {
            format: "kapsaro:format:file-enc@1".to_string(),
            sid: uuid::Uuid::new_v4(),
            wrap: vec![],
            removed_recipients: None,
            payload: crate::model::file_enc::FilePayload {
                protected: crate::model::file_enc::FilePayloadHeader {
                    format: "kapsaro:format:file-enc:payload@1".to_string(),
                    sid: uuid::Uuid::new_v4(),
                    alg: crate::model::file_enc::FileEncAlgorithm {
                        aead: "xchacha20-poly1305".to_string(),
                    },
                },
                encrypted: crate::model::file_enc::FilePayloadCiphertext {
                    nonce: "test".to_string(),
                    ct: "test".to_string(),
                },
            },
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        },
        signature: crate::model::signature::ArtifactSignature {
            alg: "eddsa-ed25519".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            mac: build_dummy_key_possession_proof(),
            sig: "test".to_string(),
        },
    };

    let proof = SignatureVerificationProof::new(
        "alice".to_string(),
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );

    let verified = VerifiedFileEncDocument::new(file_enc_doc.clone(), proof.clone());
    let (document, extracted_proof) = verified.into_inner();

    assert_eq!(document, file_enc_doc);
    assert_eq!(extracted_proof, proof);
}

#[test]
fn test_verified_binding_claims_new() {
    use crate::model::public_key::VerifiedBindingClaims;
    use crate::model::public_key::{BindingClaims, GithubAccount};
    use crate::model::verification::BindingVerificationProof;

    let claims = BindingClaims {
        github_account: Some(GithubAccount {
            id: 12345,
            login: "alice".to_string(),
        }),
    };
    let proof = BindingVerificationProof::new(
        "github".to_string(),
        Some("SHA256:abc123".to_string()),
        Some(42),
    );

    let verified = VerifiedBindingClaims::new(claims.clone(), proof.clone());

    assert_eq!(verified.claims(), &claims);
    assert_eq!(verified.proof(), &proof);
    assert_eq!(verified.claims().github_account.as_ref().unwrap().id, 12345);
    assert_eq!(verified.proof().method, "github");
    assert_eq!(verified.proof().matched_key_id, Some(42));
}

#[test]
fn test_decryption_proof_without_ssh_fpr() {
    use crate::model::verified::DecryptionProof;

    let proof = DecryptionProof::new(
        "user@example.com".to_string(),
        "01ABCDEFGHIJKLMNOPQRSTUV".to_string(),
        None,
    );
    assert!(proof.ssh_fpr().is_none());
}

#[test]
fn test_decryption_proof_with_ssh_fpr() {
    use crate::model::verified::DecryptionProof;

    let proof = DecryptionProof::new(
        "user@example.com".to_string(),
        "01ABCDEFGHIJKLMNOPQRSTUV".to_string(),
        Some("SHA256:abc123".to_string()),
    );
    assert_eq!(proof.ssh_fpr(), Some("SHA256:abc123"));
}
