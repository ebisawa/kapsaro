// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Builds typed metadata for encrypted artifact inspection.
//! Serialization and terminal rendering remain caller responsibilities.

use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::EncContent;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::model::common::{RemovedRecipient, WrapItem};
use crate::model::file_enc::FileEncDocument;
use crate::model::kv_enc::document::{KvEncDocument, KvEncEntry};
use crate::model::kv_enc::line::KvEncLine;
use crate::model::signature::ArtifactSignature;
use crate::model::verification::VerifyingKeySource;
use crate::service::inspect::OnlineVerificationDisplay;
use crate::Result;

#[derive(Debug, Clone)]
pub enum InspectMetadata {
    FileEnc(FileEncInspectMetadata),
    KvEnc(KvEncInspectMetadata),
}

#[derive(Debug, Clone)]
pub struct FileEncInspectMetadata {
    pub version: u32,
    pub header: FileEncHeaderMetadata,
    pub wrap_data: WrapDataMetadata,
    pub payload: FilePayloadMetadata,
    pub signature: ArtifactSignatureMetadata,
    pub signature_verification: SignatureVerificationMetadata,
    pub online_verification: Option<OnlineVerificationMetadata>,
}

#[derive(Debug, Clone)]
pub struct KvEncInspectMetadata {
    pub version: u32,
    pub header: KvHeaderMetadata,
    pub wrap_data: WrapDataMetadata,
    pub entries: Vec<KvEntryMetadata>,
    pub signature: ArtifactSignatureMetadata,
    pub summary: KvSummaryMetadata,
    pub signature_verification: SignatureVerificationMetadata,
    pub online_verification: Option<OnlineVerificationMetadata>,
}

#[derive(Debug, Clone)]
pub struct FileEncHeaderMetadata {
    pub format: String,
    pub sid: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct KvHeaderMetadata {
    pub sid: String,
    pub alg: AeadAlgorithmMetadata,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct WrapDataMetadata {
    pub recipients: Vec<String>,
    pub wrap_items: Vec<WrapItemMetadata>,
    pub removed_recipients: Vec<RemovedRecipientMetadata>,
}

#[derive(Debug, Clone)]
pub struct WrapItemMetadata {
    pub recipient_handle: String,
    pub kid: String,
    pub alg: String,
    pub enc: String,
    pub ct: String,
}

#[derive(Debug, Clone)]
pub struct RemovedRecipientMetadata {
    pub recipient_handle: String,
    pub kid: String,
    pub removed_at: String,
}

#[derive(Debug, Clone)]
pub struct FilePayloadMetadata {
    pub protected: FilePayloadProtectedMetadata,
    pub encrypted: PayloadCiphertextMetadata,
}

#[derive(Debug, Clone)]
pub struct FilePayloadProtectedMetadata {
    pub format: String,
    pub sid: String,
    pub alg: AeadAlgorithmMetadata,
}

#[derive(Debug, Clone)]
pub struct AeadAlgorithmMetadata {
    pub aead: String,
}

#[derive(Debug, Clone)]
pub struct PayloadCiphertextMetadata {
    pub nonce: String,
    pub ct: String,
}

#[derive(Debug, Clone)]
pub struct KvEntryMetadata {
    pub key: String,
    pub nonce: String,
    pub ct: String,
    pub disclosed: bool,
}

#[derive(Debug, Clone)]
pub struct ArtifactSignatureMetadata {
    pub alg: String,
    pub kid: String,
    pub mac: String,
    pub mac_algorithm: String,
    pub signer_public_key: SignerPublicKeyMetadata,
    pub signer_handle: String,
    pub attestation_method: String,
    pub attestation_public_key: String,
    pub sig: String,
}

#[derive(Debug, Clone)]
pub struct SignerPublicKeyMetadata {
    pub protected: SignerPublicKeyProtectedMetadata,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct SignerPublicKeyProtectedMetadata {
    pub format: String,
    pub subject_handle: String,
    pub kid: String,
    pub keys: IdentityKeysMetadata,
    pub binding_claims: Option<BindingClaimsMetadata>,
    pub attestation: AttestationMetadata,
    pub expires_at: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IdentityKeysMetadata {
    pub kem: JwkPublicKeyMetadata,
    pub sig: JwkPublicKeyMetadata,
}

#[derive(Debug, Clone)]
pub struct JwkPublicKeyMetadata {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

#[derive(Debug, Clone)]
pub struct BindingClaimsMetadata {
    pub github_account: Option<GithubAccountMetadata>,
}

#[derive(Debug, Clone)]
pub struct AttestationMetadata {
    pub method: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct SignatureVerificationMetadata {
    pub verified: bool,
    pub status: &'static str,
    pub signer_handle: Option<String>,
    pub source: Option<&'static str>,
    pub warnings: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct OnlineVerificationMetadata {
    pub provider: Option<&'static str>,
    pub status: &'static str,
    pub message: String,
    pub member_handle: Option<String>,
    pub account: Option<GithubAccountMetadata>,
    pub fingerprint: Option<String>,
    pub matched_key_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct GithubAccountMetadata {
    pub login: String,
    pub id: u64,
}

#[derive(Debug, Clone)]
pub struct KvSummaryMetadata {
    pub total_entries: usize,
}

impl From<&crate::model::public_key::PublicKey> for SignerPublicKeyMetadata {
    fn from(key: &crate::model::public_key::PublicKey) -> Self {
        Self {
            protected: SignerPublicKeyProtectedMetadata::from(&key.protected),
            signature: key.signature.clone(),
        }
    }
}

impl From<&crate::model::public_key::PublicKeyProtected> for SignerPublicKeyProtectedMetadata {
    fn from(protected: &crate::model::public_key::PublicKeyProtected) -> Self {
        Self {
            format: protected.format.clone(),
            subject_handle: protected.subject_handle.clone(),
            kid: protected.kid.clone(),
            keys: IdentityKeysMetadata::from(&protected.keys),
            binding_claims: protected
                .binding_claims
                .as_ref()
                .map(BindingClaimsMetadata::from),
            attestation: AttestationMetadata::from(&protected.attestation),
            expires_at: protected.expires_at.clone(),
            created_at: protected.created_at.clone(),
        }
    }
}

impl From<&crate::model::public_key::IdentityKeys> for IdentityKeysMetadata {
    fn from(keys: &crate::model::public_key::IdentityKeys) -> Self {
        Self {
            kem: JwkPublicKeyMetadata::from(&keys.kem),
            sig: JwkPublicKeyMetadata::from(&keys.sig),
        }
    }
}

impl From<&crate::model::public_key::JwkOkpPublicKey> for JwkPublicKeyMetadata {
    fn from(key: &crate::model::public_key::JwkOkpPublicKey) -> Self {
        Self {
            kty: key.kty.clone(),
            crv: key.crv.clone(),
            x: key.x.clone(),
        }
    }
}

impl From<&crate::model::public_key::BindingClaims> for BindingClaimsMetadata {
    fn from(claims: &crate::model::public_key::BindingClaims) -> Self {
        Self {
            github_account: claims
                .github_account
                .as_ref()
                .map(|account| GithubAccountMetadata {
                    login: account.login.clone(),
                    id: account.id,
                }),
        }
    }
}

impl From<&crate::model::public_key::Attestation> for AttestationMetadata {
    fn from(attestation: &crate::model::public_key::Attestation) -> Self {
        Self {
            method: attestation.method.clone(),
            public_key: attestation.pub_.clone(),
            signature: attestation.sig.clone(),
        }
    }
}

pub(super) fn build_inspect_metadata(
    content: &EncContent,
    report: &SignatureVerificationReport,
    online_verification: Option<OnlineVerificationMetadata>,
) -> Result<InspectMetadata> {
    let signature_verification = build_signature_verification_metadata(report);
    match content {
        EncContent::FileEnc(file_content) => {
            let doc = file_content.parse()?;
            Ok(InspectMetadata::FileEnc(build_file_enc_metadata(
                &doc,
                signature_verification,
                online_verification,
            )?))
        }
        EncContent::KvEnc(kv_content) => {
            let doc = kv_content.parse()?;
            Ok(InspectMetadata::KvEnc(build_kv_enc_metadata(
                &doc,
                signature_verification,
                online_verification,
            )?))
        }
    }
}

fn build_file_enc_metadata(
    doc: &FileEncDocument,
    signature_verification: SignatureVerificationMetadata,
    online_verification: Option<OnlineVerificationMetadata>,
) -> Result<FileEncInspectMetadata> {
    Ok(FileEncInspectMetadata {
        version: 7,
        header: build_file_enc_header_metadata(doc),
        wrap_data: build_wrap_data_metadata(
            &doc.protected.wrap,
            doc.protected.removed_recipients.as_deref(),
        ),
        payload: build_file_payload_metadata(doc),
        signature: build_artifact_signature_metadata(&doc.signature)?,
        signature_verification,
        online_verification,
    })
}

fn build_file_enc_header_metadata(doc: &FileEncDocument) -> FileEncHeaderMetadata {
    FileEncHeaderMetadata {
        format: doc.protected.format.clone(),
        sid: doc.protected.sid.to_string(),
        created_at: doc.protected.created_at.clone(),
        updated_at: doc.protected.updated_at.clone(),
    }
}

fn build_file_payload_metadata(doc: &FileEncDocument) -> FilePayloadMetadata {
    FilePayloadMetadata {
        protected: FilePayloadProtectedMetadata {
            format: doc.protected.payload.protected.format.clone(),
            sid: doc.protected.payload.protected.sid.to_string(),
            alg: AeadAlgorithmMetadata {
                aead: doc.protected.payload.protected.alg.aead.clone(),
            },
        },
        encrypted: PayloadCiphertextMetadata {
            nonce: doc.protected.payload.encrypted.nonce.clone(),
            ct: doc.protected.payload.encrypted.ct.clone(),
        },
    }
}

fn build_kv_enc_metadata(
    doc: &KvEncDocument,
    signature_verification: SignatureVerificationMetadata,
    online_verification: Option<OnlineVerificationMetadata>,
) -> Result<KvEncInspectMetadata> {
    Ok(KvEncInspectMetadata {
        version: extract_kv_enc_version(doc),
        header: build_kv_header_metadata(doc),
        wrap_data: build_wrap_data_metadata(
            &doc.wrap().wrap,
            doc.wrap().removed_recipients.as_deref(),
        ),
        entries: doc.entries().iter().map(build_kv_entry_metadata).collect(),
        signature: build_artifact_signature_metadata(doc.signature())?,
        summary: KvSummaryMetadata {
            total_entries: doc.entries().len(),
        },
        signature_verification,
        online_verification,
    })
}

fn build_kv_header_metadata(doc: &KvEncDocument) -> KvHeaderMetadata {
    KvHeaderMetadata {
        sid: doc.head().sid.to_string(),
        alg: AeadAlgorithmMetadata {
            aead: doc.head().alg.aead.clone(),
        },
        created_at: doc.head().created_at.clone(),
        updated_at: doc.head().updated_at.clone(),
    }
}

fn build_wrap_data_metadata(
    wrap_items: &[WrapItem],
    removed_recipients: Option<&[RemovedRecipient]>,
) -> WrapDataMetadata {
    WrapDataMetadata {
        recipients: wrap_items
            .iter()
            .map(|item| item.recipient_handle.clone())
            .collect(),
        wrap_items: wrap_items.iter().map(WrapItemMetadata::from).collect(),
        removed_recipients: removed_recipients
            .unwrap_or_default()
            .iter()
            .map(RemovedRecipientMetadata::from)
            .collect(),
    }
}

fn build_kv_entry_metadata(entry: &KvEncEntry) -> KvEntryMetadata {
    KvEntryMetadata {
        key: entry.key().to_string(),
        nonce: entry.value().nonce.clone(),
        ct: entry.value().ct.clone(),
        disclosed: entry.value().disclosed,
    }
}

fn build_artifact_signature_metadata(
    signature: &ArtifactSignature,
) -> Result<ArtifactSignatureMetadata> {
    Ok(ArtifactSignatureMetadata {
        alg: signature.alg.clone(),
        kid: signature.kid.clone(),
        mac: signature.mac.as_str().to_string(),
        mac_algorithm: signature.mac.algorithm().as_wire_prefix().to_string(),
        signer_public_key: SignerPublicKeyMetadata::from(&signature.signer_pub),
        signer_handle: signature.signer_pub.protected.subject_handle.clone(),
        attestation_method: signature.signer_pub.protected.attestation.method.clone(),
        attestation_public_key: signature.signer_pub.protected.attestation.pub_.clone(),
        sig: signature.sig.clone(),
    })
}

fn build_signature_verification_metadata(
    report: &SignatureVerificationReport,
) -> SignatureVerificationMetadata {
    SignatureVerificationMetadata {
        verified: report.verified,
        status: if report.verified { "ok" } else { "failed" },
        signer_handle: report.signer_handle.clone(),
        source: report.source.as_ref().map(format_verifying_key_source),
        warnings: report.warnings.clone(),
        message: report.message.clone(),
    }
}

pub(super) fn build_online_verification_metadata(
    display: &OnlineVerificationDisplay,
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> OnlineVerificationMetadata {
    match display {
        OnlineVerificationDisplay::GithubResult(result) => {
            build_github_online_verification_metadata(result, github_login, github_id)
        }
        OnlineVerificationDisplay::NoSupportedBinding => OnlineVerificationMetadata {
            provider: None,
            status: "not_configured",
            message: "no supported binding configured".to_string(),
            member_handle: None,
            account: None,
            fingerprint: None,
            matched_key_id: None,
        },
    }
}

fn build_github_online_verification_metadata(
    result: &VerificationResult,
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> OnlineVerificationMetadata {
    OnlineVerificationMetadata {
        provider: Some("github"),
        status: format_online_verification_status(result.status),
        message: result.message.clone(),
        member_handle: Some(result.member_handle.clone()),
        account: build_github_account_metadata(github_login, github_id),
        fingerprint: result.fingerprint.clone(),
        matched_key_id: result.matched_key_id,
    }
}

fn build_github_account_metadata(
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> Option<GithubAccountMetadata> {
    Some(GithubAccountMetadata {
        login: github_login?.to_string(),
        id: github_id?,
    })
}

fn format_verifying_key_source(source: &VerifyingKeySource) -> &'static str {
    match source {
        VerifyingKeySource::SignerPubEmbedded => "signer_pub_embedded",
    }
}

fn format_online_verification_status(status: VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::Verified => "verified",
        VerificationStatus::Failed => "failed",
        VerificationStatus::NotConfigured => "not_configured",
    }
}

fn extract_kv_enc_version(doc: &KvEncDocument) -> u32 {
    doc.lines()
        .iter()
        .find_map(|line| match line {
            KvEncLine::Header { version } => Some(version.as_u32()),
            _ => None,
        })
        .unwrap_or(9)
}

impl From<&WrapItem> for WrapItemMetadata {
    fn from(item: &WrapItem) -> Self {
        Self {
            recipient_handle: item.recipient_handle.clone(),
            kid: item.kid.clone(),
            alg: item.alg.clone(),
            enc: item.enc.clone(),
            ct: item.ct.clone(),
        }
    }
}

impl From<&RemovedRecipient> for RemovedRecipientMetadata {
    fn from(item: &RemovedRecipient) -> Self {
        Self {
            recipient_handle: item.recipient_handle.clone(),
            kid: item.kid.clone(),
            removed_at: item.removed_at.clone(),
        }
    }
}
