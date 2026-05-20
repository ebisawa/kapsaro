// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact key-possession proof orchestration.
//!
//! Bridges canonical artifact body bytes and content-key HMAC verification.

use crate::crypto::hmac::{compute_hmac_sha256_tag, verify_hmac_sha256_tag};
use crate::crypto::types::keys::MasterKey;
use crate::format::file::build_file_signature_bytes;
use crate::format::kv::enc::canonical::build_canonical_bytes;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::model::signature::{KeyPossessionProof, KeyPossessionProofAlgorithm};
use crate::model::wire::context::MAC_DOMAIN_KEY_POSSESSION_V1;
use crate::{Error, Result};

pub struct VerifiedFileKeyPossession<'a> {
    document: &'a VerifiedFileEncDocument,
    content_key: MasterKey,
}

impl<'a> VerifiedFileKeyPossession<'a> {
    pub fn new(document: &'a VerifiedFileEncDocument, content_key: MasterKey) -> Self {
        Self {
            document,
            content_key,
        }
    }

    pub fn document(&self) -> &'a VerifiedFileEncDocument {
        self.document
    }

    pub fn content_key(&self) -> &MasterKey {
        &self.content_key
    }

    pub fn into_content_key(self) -> MasterKey {
        self.content_key
    }
}

pub struct VerifiedKvKeyPossession<'a> {
    document: &'a VerifiedKvEncDocument,
    master_key: MasterKey,
}

impl<'a> VerifiedKvKeyPossession<'a> {
    pub fn new(document: &'a VerifiedKvEncDocument, master_key: MasterKey) -> Self {
        Self {
            document,
            master_key,
        }
    }

    pub fn document(&self) -> &'a VerifiedKvEncDocument {
        self.document
    }

    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    pub fn into_master_key(self) -> MasterKey {
        self.master_key
    }
}

pub fn build_file_key_possession_proof(
    protected: &crate::model::file_enc::FileEncDocumentProtected,
    content_key: &MasterKey,
    signer_kid: &str,
) -> Result<KeyPossessionProof> {
    let body_bytes = build_file_signature_bytes(protected)?;
    build_key_possession_proof(&body_bytes, content_key, signer_kid)
}

pub fn build_kv_key_possession_proof(
    unsigned: &str,
    master_key: &MasterKey,
    signer_kid: &str,
) -> Result<KeyPossessionProof> {
    build_key_possession_proof(unsigned.as_bytes(), master_key, signer_kid)
}

pub fn build_key_possession_sig_input(body_bytes: &[u8], proof: &KeyPossessionProof) -> Vec<u8> {
    let mut input = Vec::with_capacity(body_bytes.len() + proof.as_str().len());
    input.extend_from_slice(body_bytes);
    input.extend_from_slice(proof.as_str().as_bytes());
    input
}

pub fn verify_file_key_possession<'a>(
    document: &'a VerifiedFileEncDocument,
    content_key: MasterKey,
) -> Result<VerifiedFileKeyPossession<'a>> {
    let body_bytes = build_file_signature_bytes(&document.document().protected)?;
    verify_key_possession_proof(
        &document.document().signature.mac,
        content_key.as_bytes(),
        &body_bytes,
        &document.document().signature.kid,
    )?;
    Ok(VerifiedFileKeyPossession::new(document, content_key))
}

pub fn verify_kv_key_possession<'a>(
    document: &'a VerifiedKvEncDocument,
    master_key: MasterKey,
) -> Result<VerifiedKvKeyPossession<'a>> {
    let body_bytes = build_canonical_bytes(document.document().lines());
    verify_key_possession_proof(
        &document.document().signature().mac,
        master_key.as_bytes(),
        &body_bytes,
        &document.document().signature().kid,
    )?;
    Ok(VerifiedKvKeyPossession::new(document, master_key))
}

fn build_key_possession_proof(
    body_bytes: &[u8],
    content_key: &MasterKey,
    signer_kid: &str,
) -> Result<KeyPossessionProof> {
    let algorithm = KeyPossessionProofAlgorithm::HmacSha256;
    let tag =
        compute_key_possession_tag(algorithm, content_key.as_bytes(), body_bytes, signer_kid)?;
    KeyPossessionProof::try_new(algorithm, &tag)
        .map_err(|e| Error::build_crypto_error(format!("Key-possession proof error: {e}")))
}

fn verify_key_possession_proof(
    proof: &KeyPossessionProof,
    key: &[u8],
    body_bytes: &[u8],
    signer_kid: &str,
) -> Result<()> {
    let is_valid =
        verify_key_possession_tag(proof.algorithm(), key, body_bytes, signer_kid, proof.tag())?;
    if is_valid {
        Ok(())
    } else {
        Err(Error::build_verification_error(
            "E_KEY_POSSESSION_MAC_INVALID",
            "Key-possession proof verification failed",
        ))
    }
}

fn compute_key_possession_tag(
    algorithm: KeyPossessionProofAlgorithm,
    key: &[u8],
    body_bytes: &[u8],
    signer_kid: &str,
) -> Result<Vec<u8>> {
    match algorithm {
        KeyPossessionProofAlgorithm::HmacSha256 => {
            let message = build_key_possession_mac_message(body_bytes, signer_kid);
            compute_hmac_sha256_tag(key, &message)
        }
    }
}

fn verify_key_possession_tag(
    algorithm: KeyPossessionProofAlgorithm,
    key: &[u8],
    body_bytes: &[u8],
    signer_kid: &str,
    expected_tag: &[u8],
) -> Result<bool> {
    match algorithm {
        KeyPossessionProofAlgorithm::HmacSha256 => {
            let message = build_key_possession_mac_message(body_bytes, signer_kid);
            verify_hmac_sha256_tag(key, &message, expected_tag)
        }
    }
}

fn build_key_possession_mac_message(body_bytes: &[u8], signer_kid: &str) -> Vec<u8> {
    let domain = MAC_DOMAIN_KEY_POSSESSION_V1.as_bytes();
    let kid = signer_kid.as_bytes();
    let mut message = Vec::with_capacity(domain.len() + body_bytes.len() + kid.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(body_bytes);
    message.extend_from_slice(kid);
    message
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_envelope_key_possession_test.rs"]
mod tests;
