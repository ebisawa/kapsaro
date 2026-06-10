// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::feature::inspect::build_section;
use crate::feature::inspect::verification::build_signature_verification_section;
use crate::feature::inspect::{
    build_inspect_view, InspectOutput as FeatureInspectOutput,
    InspectSection as FeatureInspectSection,
};
use crate::feature::verify::file::verify_file_document_report;
use crate::feature::verify::kv::signature::verify_kv_document_report;
use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::EncContent;
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::model::common::{RemovedRecipient, WrapItem};
use crate::model::file_enc::FileEncDocument;
use crate::model::kv_enc::document::{KvEncDocument, KvEncEntry};
use crate::model::kv_enc::line::KvEncLine;
use crate::model::public_key::GithubAccount;
use crate::model::signature::ArtifactSignature;
use crate::model::verification::VerifyingKeySource;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::runtime::block_on_result;
use crate::Result;

pub struct InspectCommand {
    pub input_display: String,
    pub output: InspectOutput,
    pub json_output: InspectJsonOutput,
}

struct GithubAccountDisplayValues {
    login: String,
    id: u64,
}

struct OnlineVerificationOutput {
    section: InspectSection,
    json: OnlineVerificationJsonOutput,
}

/// Online verification display variants.
pub enum OnlineVerificationDisplay {
    /// GitHub verification result available.
    GithubResult(VerificationResult),
    /// Binding claims exist but no supported binding is configured.
    NoSupportedBinding,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InspectOutput {
    pub title: String,
    pub sections: Vec<InspectSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InspectSection {
    pub title: String,
    pub lines: Vec<String>,
}

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
struct OnlineVerificationJsonOutput {
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

impl From<FeatureInspectOutput> for InspectOutput {
    fn from(output: FeatureInspectOutput) -> Self {
        Self {
            title: output.title,
            sections: output
                .sections
                .into_iter()
                .map(InspectSection::from)
                .collect(),
        }
    }
}

impl From<FeatureInspectSection> for InspectSection {
    fn from(section: FeatureInspectSection) -> Self {
        Self {
            title: section.title,
            lines: section.lines,
        }
    }
}

pub fn execute_inspect_file_command(
    options: &CommonCommandOptions,
    input_path: &Path,
) -> Result<InspectCommand> {
    let content = load_inspect_content(input_path)?;
    let mut inspect_output = InspectOutput::from(build_inspect_view(&content)?);
    let signature_report = build_signature_report(&content, options.debug)?;
    let online_output = build_online_output(options, &signature_report);

    inspect_output
        .sections
        .push(build_signature_verification_section(&signature_report).into());

    if let Some(online) = &online_output {
        inspect_output.sections.push(online.section.clone());
    }

    let json_output = build_inspect_json_output(
        &content,
        &signature_report,
        online_output.as_ref().map(|online| online.json.clone()),
    )?;

    Ok(InspectCommand {
        input_display: format_path_relative_to_cwd(input_path),
        output: inspect_output,
        json_output,
    })
}

fn load_inspect_content(input_path: &Path) -> Result<EncContent> {
    EncContent::detect_with_source(
        load_text_with_limit(
            input_path,
            resolve_encrypted_artifact_read_limit(input_path),
            "encrypted artifact",
        )?,
        format_path_relative_to_cwd(input_path),
    )
}

fn build_signature_report(
    content: &EncContent,
    debug: bool,
) -> Result<SignatureVerificationReport> {
    Ok(match content {
        EncContent::FileEnc(file_content) => {
            let doc = file_content.parse()?;
            verify_file_document_report(&doc, debug)
        }
        EncContent::KvEnc(kv_content) => verify_kv_document_report(kv_content.as_str(), debug),
    })
}

fn build_online_output(
    options: &CommonCommandOptions,
    report: &SignatureVerificationReport,
) -> Option<OnlineVerificationOutput> {
    let public_key = report.signer_public_key.as_ref()?;
    if !report.verified {
        return None;
    }

    let binding_claims = public_key.protected.binding_claims.as_ref()?;
    let github = match binding_claims.github_account.as_ref() {
        Some(github) => github,
        None => {
            let display = OnlineVerificationDisplay::NoSupportedBinding;
            return Some(build_online_output_from_display(&display, None, None));
        }
    };

    let result = match block_on_result(verify_github_account(public_key, options.debug)) {
        Ok(result) => result,
        Err(err) => build_failed_online_verification_result(
            &public_key.protected.subject_handle,
            err.format_user_message().to_string(),
            None,
            true,
        ),
    };
    let github_display = build_github_account_display_values(&result, github);
    let display = OnlineVerificationDisplay::GithubResult(result);
    Some(build_online_output_from_display(
        &display,
        Some(github_display.login.as_str()),
        Some(github_display.id),
    ))
}

fn build_online_output_from_display(
    display: &OnlineVerificationDisplay,
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> OnlineVerificationOutput {
    OnlineVerificationOutput {
        section: build_online_verification_section(display, github_login, github_id),
        json: build_online_verification_json_output(display, github_login, github_id),
    }
}

pub fn build_online_verification_section(
    display: &OnlineVerificationDisplay,
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> InspectSection {
    match display {
        OnlineVerificationDisplay::GithubResult(result) => {
            let mut lines = Vec::new();
            match result.status {
                VerificationStatus::Verified => {
                    lines.push("  Status:      \u{2714} OK".to_string());
                    if let (Some(login), Some(id)) = (github_login, github_id) {
                        lines.push(format!("  Account:     {} (id: {})", login, id));
                    }
                    if let Some(ref fp) = result.fingerprint {
                        lines.push(format!("  SSH key:     {}", fp));
                    }
                    if let Some(key_id) = result.matched_key_id {
                        lines.push(format!("  Matched ID:  {}", key_id));
                    }
                }
                VerificationStatus::Failed | VerificationStatus::NotConfigured => {
                    lines.push("  Status:      \u{2718} FAILED".to_string());
                    lines.push(format!("  Reason:      {}", result.message));
                }
            }
            build_section("Online Verification (GitHub)", lines).into()
        }
        OnlineVerificationDisplay::NoSupportedBinding => build_section(
            "Online Verification",
            vec!["  Status:      Not available (no supported binding configured)".to_string()],
        )
        .into(),
    }
}

fn build_github_account_display_values(
    result: &VerificationResult,
    github_claim: &GithubAccount,
) -> GithubAccountDisplayValues {
    match result.verified_github.as_ref() {
        Some(verified) => GithubAccountDisplayValues {
            login: verified.login.clone(),
            id: verified.id,
        },
        None => GithubAccountDisplayValues {
            login: github_claim.login.clone(),
            id: github_claim.id,
        },
    }
}

fn build_inspect_json_output(
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
        header: FileEncHeaderJsonOutput {
            format: doc.protected.format.clone(),
            sid: doc.protected.sid.to_string(),
            created_at: doc.protected.created_at.clone(),
            updated_at: doc.protected.updated_at.clone(),
        },
        wrap_data: build_wrap_data_json_output(
            &doc.protected.wrap,
            doc.protected.removed_recipients.as_deref(),
        ),
        payload: FilePayloadJsonOutput {
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
        },
        signature: build_artifact_signature_json_output(&doc.signature)?,
        signature_verification,
        online_verification,
    })
}

fn build_kv_enc_json_output(
    doc: &KvEncDocument,
    signature_verification: SignatureVerificationJsonOutput,
    online_verification: Option<OnlineVerificationJsonOutput>,
) -> Result<KvEncInspectJsonOutput> {
    Ok(KvEncInspectJsonOutput {
        version: extract_kv_enc_version(doc),
        header: KvHeaderJsonOutput {
            sid: doc.head().sid.to_string(),
            alg: AeadAlgorithmJsonOutput {
                aead: doc.head().alg.aead.clone(),
            },
            created_at: doc.head().created_at.clone(),
            updated_at: doc.head().updated_at.clone(),
        },
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

fn build_online_verification_json_output(
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

fn build_failed_online_verification_result(
    member_handle: &str,
    message: String,
    fingerprint: Option<String>,
    github_claim_present: bool,
) -> VerificationResult {
    VerificationResult {
        member_handle: member_handle.to_string(),
        status: VerificationStatus::Failed,
        message,
        fingerprint,
        matched_key_id: None,
        github_claim_present,
        verified_github: None,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_inspect_verification_test.rs"]
mod feature_inspect_verification_test;
