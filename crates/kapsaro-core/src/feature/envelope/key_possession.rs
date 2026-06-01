// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact key-possession proof orchestration.
//!
//! Bridges canonical artifact body bytes and content-key HMAC verification.

use crate::crypto::hmac::{compute_hmac_sha256_tag, verify_hmac_sha256_tag};
use crate::crypto::types::keys::{MacKey, MasterKey, XChaChaKey};
use crate::feature::envelope::key_schedule::{FileKeySchedule, KvKeySchedule};
use crate::format::signature::{
    build_file_artifact_body_bytes, build_key_possession_mac_message, build_kv_artifact_body_bytes,
    ArtifactBodyBytes,
};
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::model::signature::{KeyPossessionProof, KeyPossessionProofAlgorithm};
use crate::support::kid::format_kid_half_display_lossy;
use crate::{Error, Result};
use tracing::debug;

pub struct VerifiedFileKeyPossession<'a> {
    document: &'a VerifiedFileEncDocument,
    master_key: MasterKey,
    content_key: XChaChaKey,
}

impl<'a> VerifiedFileKeyPossession<'a> {
    pub fn new(
        document: &'a VerifiedFileEncDocument,
        master_key: MasterKey,
        content_key: XChaChaKey,
    ) -> Self {
        Self {
            document,
            master_key,
            content_key,
        }
    }

    pub fn document(&self) -> &'a VerifiedFileEncDocument {
        self.document
    }

    pub fn content_key(&self) -> &XChaChaKey {
        &self.content_key
    }

    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    pub fn into_content_key(self) -> XChaChaKey {
        self.content_key
    }

    pub fn into_master_key(self) -> MasterKey {
        self.master_key
    }
}

pub struct VerifiedKvKeyPossession<'a> {
    _document: &'a VerifiedKvEncDocument,
    master_key: MasterKey,
    key_schedule: KvKeySchedule,
}

impl<'a> VerifiedKvKeyPossession<'a> {
    pub fn new(
        document: &'a VerifiedKvEncDocument,
        master_key: MasterKey,
        key_schedule: KvKeySchedule,
    ) -> Self {
        Self {
            _document: document,
            master_key,
            key_schedule,
        }
    }

    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    pub fn key_schedule(&self) -> &KvKeySchedule {
        &self.key_schedule
    }

    pub fn into_master_key(self) -> MasterKey {
        self.master_key
    }
}

pub fn build_file_key_possession_proof(
    body_bytes: &ArtifactBodyBytes,
    mac_key: &MacKey,
    signer_kid: &str,
    debug_enabled: bool,
) -> Result<KeyPossessionProof> {
    build_key_possession_proof("file", body_bytes, mac_key, signer_kid, debug_enabled)
}

pub fn build_kv_key_possession_proof(
    body_bytes: &ArtifactBodyBytes,
    mac_key: &MacKey,
    signer_kid: &str,
    debug_enabled: bool,
) -> Result<KeyPossessionProof> {
    build_key_possession_proof("kv", body_bytes, mac_key, signer_kid, debug_enabled)
}

pub fn verify_file_key_possession<'a>(
    document: &'a VerifiedFileEncDocument,
    master_key: MasterKey,
    debug_enabled: bool,
) -> Result<VerifiedFileKeyPossession<'a>> {
    let body_bytes = build_file_artifact_body_bytes(&document.document().protected)?;
    debug_key_possession_hkdf_extract("file", debug_enabled);
    let schedule = FileKeySchedule::extract(&master_key, &document.document().protected.sid)?;
    debug_key_possession_hkdf_expand("file", "mac key", debug_enabled);
    let mac_key = schedule.derive_mac_key()?;
    verify_key_possession_proof(
        "file",
        &document.document().signature.mac,
        &mac_key,
        &body_bytes,
        &document.document().signature.kid,
        debug_enabled,
    )?;
    debug_key_possession_hkdf_expand("file", "content key", debug_enabled);
    let content_key = schedule.derive_content_key()?;
    Ok(VerifiedFileKeyPossession::new(
        document,
        master_key,
        content_key,
    ))
}

pub fn verify_kv_key_possession<'a>(
    document: &'a VerifiedKvEncDocument,
    master_key: MasterKey,
    debug_enabled: bool,
) -> Result<VerifiedKvKeyPossession<'a>> {
    let body_bytes = build_kv_artifact_body_bytes(document.document());
    debug_key_possession_hkdf_extract("kv", debug_enabled);
    let schedule = KvKeySchedule::extract(&master_key, &document.document().head().sid)?;
    debug_key_possession_hkdf_expand("kv", "mac key", debug_enabled);
    let mac_key = schedule.derive_mac_key()?;
    verify_key_possession_proof(
        "kv",
        &document.document().signature().mac,
        &mac_key,
        &body_bytes,
        &document.document().signature().kid,
        debug_enabled,
    )?;
    Ok(VerifiedKvKeyPossession::new(document, master_key, schedule))
}

fn build_key_possession_proof(
    format: &str,
    body_bytes: &ArtifactBodyBytes,
    mac_key: &MacKey,
    signer_kid: &str,
    debug_enabled: bool,
) -> Result<KeyPossessionProof> {
    let algorithm = KeyPossessionProofAlgorithm::HmacSha256;
    if debug_enabled {
        debug!(
            "[CRYPTO] key possession: build proof format={}, alg=hmac-sha256 (kid: {})",
            format,
            format_kid_half_display_lossy(signer_kid)
        );
    }
    let tag = compute_key_possession_tag(
        algorithm,
        mac_key,
        body_bytes,
        signer_kid,
        format,
        debug_enabled,
    )?;
    KeyPossessionProof::try_new(algorithm, &tag)
        .map_err(|e| Error::build_crypto_error(format!("Key-possession proof error: {e}")))
}

fn verify_key_possession_proof(
    format: &str,
    proof: &KeyPossessionProof,
    key: &MacKey,
    body_bytes: &ArtifactBodyBytes,
    signer_kid: &str,
    debug_enabled: bool,
) -> Result<()> {
    if debug_enabled {
        debug!(
            "[CRYPTO] key possession: verify start format={}, alg=hmac-sha256 (kid: {})",
            format,
            format_kid_half_display_lossy(signer_kid)
        );
    }
    let is_valid = verify_key_possession_tag(
        proof.algorithm(),
        key,
        body_bytes,
        signer_kid,
        proof.tag(),
        format,
        debug_enabled,
    )?;
    if is_valid {
        if debug_enabled {
            debug!(
                "[CRYPTO] key possession: verify success (kid: {})",
                format_kid_half_display_lossy(signer_kid)
            );
        }
        Ok(())
    } else {
        if debug_enabled {
            debug!(
                "[CRYPTO] key possession: verify failure (kid: {})",
                format_kid_half_display_lossy(signer_kid)
            );
        }
        Err(Error::build_verification_error(
            "E_KEY_POSSESSION_MAC_INVALID",
            "Key-possession proof verification failed",
        ))
    }
}

fn debug_key_possession_hkdf_extract(format: &str, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[CRYPTO] HKDF-SHA256: key possession: extract artifact key schedule format={}",
            format
        );
    }
}

fn debug_key_possession_hkdf_expand(format: &str, purpose: &str, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[CRYPTO] HKDF-SHA256: key possession: expand {} format={}",
            purpose, format
        );
    }
}

fn debug_key_possession_hmac_message(operation: &str, format: &str, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[CRYPTO] HMAC-SHA256: key possession: build {} message format={}",
            operation, format
        );
    }
}

fn debug_key_possession_hmac_tag(operation: &str, format: &str, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[CRYPTO] HMAC-SHA256: key possession: {} tag format={}",
            operation, format
        );
    }
}

fn compute_key_possession_tag(
    algorithm: KeyPossessionProofAlgorithm,
    key: &MacKey,
    body_bytes: &ArtifactBodyBytes,
    signer_kid: &str,
    format: &str,
    debug_enabled: bool,
) -> Result<Vec<u8>> {
    match algorithm {
        KeyPossessionProofAlgorithm::HmacSha256 => {
            debug_key_possession_hmac_message("proof", format, debug_enabled);
            let message = build_key_possession_mac_message(body_bytes, signer_kid);
            debug_key_possession_hmac_tag("compute", format, debug_enabled);
            compute_hmac_sha256_tag(key.as_bytes(), &message)
        }
    }
}

fn verify_key_possession_tag(
    algorithm: KeyPossessionProofAlgorithm,
    key: &MacKey,
    body_bytes: &ArtifactBodyBytes,
    signer_kid: &str,
    expected_tag: &[u8],
    format: &str,
    debug_enabled: bool,
) -> Result<bool> {
    match algorithm {
        KeyPossessionProofAlgorithm::HmacSha256 => {
            debug_key_possession_hmac_message("verification", format, debug_enabled);
            let message = build_key_possession_mac_message(body_bytes, signer_kid);
            debug_key_possession_hmac_tag("verify", format, debug_enabled);
            verify_hmac_sha256_tag(key.as_bytes(), &message, expected_tag)
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_envelope_key_possession_test.rs"]
mod tests;
