// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Builds serde DTOs for inspect command JSON output.
// Keeps wire-facing JSON shape separate from inspect orchestration.

use crate::app::file::inspect::OnlineVerificationDisplay;
use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::EncContent;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::model::common::{RemovedRecipient, WrapItem};
use crate::model::file_enc::FileEncDocument;
use crate::model::kv_enc::document::{KvEncDocument, KvEncEntry};
use crate::model::kv_enc::line::KvEncLine;
use crate::model::signature::ArtifactSignature;
use crate::model::verification::VerifyingKeySource;
use crate::Result;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "format")]
pub enum InspectJsonOutput {
    #[serde(rename = "file-enc")]
    FileEnc(FileEncInspectJsonOutput),
    #[serde(rename = "kv-enc")]
    KvEnc(KvEncInspectJsonOutput),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileEncInspectJsonOutput {
    version: u32,
    header: FileEncHeaderJsonOutput,
    wrap_data: WrapDataJsonOutput,
    payload: FilePayloadJsonOutput,
    signature: ArtifactSignatureJsonOutput,
    signature_verification: SignatureVerificationJsonOutput,
    online_verification: Option<OnlineVerificationJsonOutput>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KvEncInspectJsonOutput {
    version: u32,
    header: KvHeaderJsonOutput,
    wrap_data: WrapDataJsonOutput,
    entries: Vec<KvEntryJsonOutput>,
    signature: ArtifactSignatureJsonOutput,
    summary: KvSummaryJsonOutput,
    signature_verification: SignatureVerificationJsonOutput,
    online_verification: Option<OnlineVerificationJsonOutput>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FileEncHeaderJsonOutput {
    format: String,
    sid: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct KvHeaderJsonOutput {
    sid: String,
    alg: AeadAlgorithmJsonOutput,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct WrapDataJsonOutput {
    recipients: Vec<String>,
    wrap_items: Vec<WrapItemJsonOutput>,
    removed_recipients: Vec<RemovedRecipientJsonOutput>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct WrapItemJsonOutput {
    recipient_handle: String,
    kid: String,
    alg: String,
    enc: String,
    ct: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RemovedRecipientJsonOutput {
    recipient_handle: String,
    kid: String,
    removed_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FilePayloadJsonOutput {
    protected: FilePayloadProtectedJsonOutput,
    encrypted: PayloadCiphertextJsonOutput,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FilePayloadProtectedJsonOutput {
    format: String,
    sid: String,
    alg: AeadAlgorithmJsonOutput,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AeadAlgorithmJsonOutput {
    aead: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct PayloadCiphertextJsonOutput {
    nonce: String,
    ct: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct KvEntryJsonOutput {
    key: String,
    nonce: String,
    ct: String,
    disclosed: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ArtifactSignatureJsonOutput {
    alg: String,
    kid: String,
    mac: String,
    signer_pub: serde_json::Value,
    sig: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SignatureVerificationJsonOutput {
    verified: bool,
    status: &'static str,
    signer_handle: Option<String>,
    source: Option<&'static str>,
    warnings: Vec<String>,
    message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct OnlineVerificationJsonOutput {
    provider: Option<&'static str>,
    status: &'static str,
    message: String,
    member_handle: Option<String>,
    account: Option<GithubAccountJsonOutput>,
    fingerprint: Option<String>,
    matched_key_id: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct GithubAccountJsonOutput {
    login: String,
    id: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct KvSummaryJsonOutput {
    total_entries: usize,
}

pub(super) fn build_inspect_json_output(
    content: &EncContent,
    report: &SignatureVerificationReport,
    online_verification: Option<OnlineVerificationJsonOutput>,
) -> Result<InspectJsonOutput> {
    let signature_verification = build_signature_verification_json_output(report);
    match content {
        EncContent::FileEnc(file_content) => {
            let doc = file_content.parse()?;
            Ok(InspectJsonOutput::FileEnc(build_file_enc_json_output(
                &doc,
                signature_verification,
                online_verification,
            )?))
        }
        EncContent::KvEnc(kv_content) => {
            let doc = kv_content.parse()?;
            Ok(InspectJsonOutput::KvEnc(build_kv_enc_json_output(
                &doc,
                signature_verification,
                online_verification,
            )?))
        }
    }
}

fn build_file_enc_json_output(
    doc: &FileEncDocument,
    signature_verification: SignatureVerificationJsonOutput,
    online_verification: Option<OnlineVerificationJsonOutput>,
) -> Result<FileEncInspectJsonOutput> {
    Ok(FileEncInspectJsonOutput {
        version: 7,
        header: build_file_enc_header_json_output(doc),
        wrap_data: build_wrap_data_json_output(
            &doc.protected.wrap,
            doc.protected.removed_recipients.as_deref(),
        ),
        payload: build_file_payload_json_output(doc),
        signature: build_artifact_signature_json_output(&doc.signature)?,
        signature_verification,
        online_verification,
    })
}

fn build_file_enc_header_json_output(doc: &FileEncDocument) -> FileEncHeaderJsonOutput {
    FileEncHeaderJsonOutput {
        format: doc.protected.format.clone(),
        sid: doc.protected.sid.to_string(),
        created_at: doc.protected.created_at.clone(),
        updated_at: doc.protected.updated_at.clone(),
    }
}

fn build_file_payload_json_output(doc: &FileEncDocument) -> FilePayloadJsonOutput {
    FilePayloadJsonOutput {
        protected: FilePayloadProtectedJsonOutput {
            format: doc.protected.payload.protected.format.clone(),
            sid: doc.protected.payload.protected.sid.to_string(),
            alg: AeadAlgorithmJsonOutput {
                aead: doc.protected.payload.protected.alg.aead.clone(),
            },
        },
        encrypted: PayloadCiphertextJsonOutput {
            nonce: doc.protected.payload.encrypted.nonce.clone(),
            ct: doc.protected.payload.encrypted.ct.clone(),
        },
    }
}

fn build_kv_enc_json_output(
    doc: &KvEncDocument,
    signature_verification: SignatureVerificationJsonOutput,
    online_verification: Option<OnlineVerificationJsonOutput>,
) -> Result<KvEncInspectJsonOutput> {
    Ok(KvEncInspectJsonOutput {
        version: extract_kv_enc_version(doc),
        header: build_kv_header_json_output(doc),
        wrap_data: build_wrap_data_json_output(
            &doc.wrap().wrap,
            doc.wrap().removed_recipients.as_deref(),
        ),
        entries: doc
            .entries()
            .iter()
            .map(build_kv_entry_json_output)
            .collect(),
        signature: build_artifact_signature_json_output(doc.signature())?,
        summary: KvSummaryJsonOutput {
            total_entries: doc.entries().len(),
        },
        signature_verification,
        online_verification,
    })
}

fn build_kv_header_json_output(doc: &KvEncDocument) -> KvHeaderJsonOutput {
    KvHeaderJsonOutput {
        sid: doc.head().sid.to_string(),
        alg: AeadAlgorithmJsonOutput {
            aead: doc.head().alg.aead.clone(),
        },
        created_at: doc.head().created_at.clone(),
        updated_at: doc.head().updated_at.clone(),
    }
}

fn build_wrap_data_json_output(
    wrap_items: &[WrapItem],
    removed_recipients: Option<&[RemovedRecipient]>,
) -> WrapDataJsonOutput {
    WrapDataJsonOutput {
        recipients: wrap_items
            .iter()
            .map(|item| item.recipient_handle.clone())
            .collect(),
        wrap_items: wrap_items.iter().map(WrapItemJsonOutput::from).collect(),
        removed_recipients: removed_recipients
            .unwrap_or_default()
            .iter()
            .map(RemovedRecipientJsonOutput::from)
            .collect(),
    }
}

fn build_kv_entry_json_output(entry: &KvEncEntry) -> KvEntryJsonOutput {
    KvEntryJsonOutput {
        key: entry.key().to_string(),
        nonce: entry.value().nonce.clone(),
        ct: entry.value().ct.clone(),
        disclosed: entry.value().disclosed,
    }
}

fn build_artifact_signature_json_output(
    signature: &ArtifactSignature,
) -> Result<ArtifactSignatureJsonOutput> {
    Ok(ArtifactSignatureJsonOutput {
        alg: signature.alg.clone(),
        kid: signature.kid.clone(),
        mac: signature.mac.as_str().to_string(),
        signer_pub: serde_json::to_value(&signature.signer_pub)?,
        sig: signature.sig.clone(),
    })
}

fn build_signature_verification_json_output(
    report: &SignatureVerificationReport,
) -> SignatureVerificationJsonOutput {
    SignatureVerificationJsonOutput {
        verified: report.verified,
        status: if report.verified { "ok" } else { "failed" },
        signer_handle: report.signer_handle.clone(),
        source: report.source.as_ref().map(format_verifying_key_source),
        warnings: report.warnings.clone(),
        message: report.message.clone(),
    }
}

pub(super) fn build_online_verification_json_output(
    display: &OnlineVerificationDisplay,
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> OnlineVerificationJsonOutput {
    match display {
        OnlineVerificationDisplay::GithubResult(result) => {
            build_github_online_verification_json_output(result, github_login, github_id)
        }
        OnlineVerificationDisplay::NoSupportedBinding => OnlineVerificationJsonOutput {
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

fn build_github_online_verification_json_output(
    result: &VerificationResult,
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> OnlineVerificationJsonOutput {
    OnlineVerificationJsonOutput {
        provider: Some("github"),
        status: format_online_verification_status(result.status),
        message: result.message.clone(),
        member_handle: Some(result.member_handle.clone()),
        account: build_github_account_json_output(github_login, github_id),
        fingerprint: result.fingerprint.clone(),
        matched_key_id: result.matched_key_id,
    }
}

fn build_github_account_json_output(
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> Option<GithubAccountJsonOutput> {
    Some(GithubAccountJsonOutput {
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

impl From<&WrapItem> for WrapItemJsonOutput {
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

impl From<&RemovedRecipient> for RemovedRecipientJsonOutput {
    fn from(item: &RemovedRecipient) -> Self {
        Self {
            recipient_handle: item.recipient_handle.clone(),
            kid: item.kid.clone(),
            removed_at: item.removed_at.clone(),
        }
    }
}
