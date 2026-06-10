// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Collects inspect content and verification reports from lower layers.
// Resolves online verification data into text and JSON-ready sections.

use std::path::Path;

use super::json::{build_online_verification_json_output, OnlineVerificationJsonOutput};
use super::{InspectSection, OnlineVerificationDisplay};
use crate::app::context::options::CommonCommandOptions;
use crate::feature::inspect::build_section;
use crate::feature::verify::file::verify_file_document_report;
use crate::feature::verify::kv::signature::verify_kv_document_report;
use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::EncContent;
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::model::public_key::GithubAccount;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::runtime::block_on_result;
use crate::Result;

struct GithubAccountDisplayValues {
    login: String,
    id: u64,
}

pub(super) struct OnlineVerificationOutput {
    pub(super) section: InspectSection,
    pub(super) json: OnlineVerificationJsonOutput,
}

pub(super) fn load_inspect_content(input_path: &Path) -> Result<EncContent> {
    EncContent::detect_with_source(
        load_text_with_limit(
            input_path,
            resolve_encrypted_artifact_read_limit(input_path),
            "encrypted artifact",
        )?,
        format_path_relative_to_cwd(input_path),
    )
}

pub(super) fn build_signature_report(
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

pub(super) fn build_online_output(
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
    let result = verify_online_github_account(public_key, options.debug);
    let github_display = build_github_account_display_values(&result, github);
    let display = OnlineVerificationDisplay::GithubResult(result);

    Some(build_online_output_from_display(
        &display,
        Some(github_display.login.as_str()),
        Some(github_display.id),
    ))
}

fn verify_online_github_account(
    public_key: &crate::model::public_key::PublicKey,
    debug: bool,
) -> VerificationResult {
    match block_on_result(verify_github_account(public_key, debug)) {
        Ok(result) => result,
        Err(err) => build_failed_online_verification_result(
            &public_key.protected.subject_handle,
            err.format_user_message().to_string(),
            None,
            true,
        ),
    }
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
            build_github_online_verification_section(result, github_login, github_id)
        }
        OnlineVerificationDisplay::NoSupportedBinding => build_section(
            "Online Verification",
            vec!["  Status:      Not available (no supported binding configured)".to_string()],
        )
        .into(),
    }
}

fn build_github_online_verification_section(
    result: &VerificationResult,
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> InspectSection {
    build_section(
        "Online Verification (GitHub)",
        build_github_online_verification_lines(result, github_login, github_id),
    )
    .into()
}

fn build_github_online_verification_lines(
    result: &VerificationResult,
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> Vec<String> {
    match result.status {
        VerificationStatus::Verified => {
            build_verified_github_online_verification_lines(result, github_login, github_id)
        }
        VerificationStatus::Failed | VerificationStatus::NotConfigured => {
            build_failed_github_online_verification_lines(result)
        }
    }
}

fn build_verified_github_online_verification_lines(
    result: &VerificationResult,
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> Vec<String> {
    let mut lines = vec!["  Status:      \u{2714} OK".to_string()];
    if let (Some(login), Some(id)) = (github_login, github_id) {
        lines.push(format!("  Account:     {} (id: {})", login, id));
    }
    if let Some(ref fp) = result.fingerprint {
        lines.push(format!("  SSH key:     {}", fp));
    }
    if let Some(key_id) = result.matched_key_id {
        lines.push(format!("  Matched ID:  {}", key_id));
    }
    lines
}

fn build_failed_github_online_verification_lines(result: &VerificationResult) -> Vec<String> {
    vec![
        "  Status:      \u{2718} FAILED".to_string(),
        format!("  Reason:      {}", result.message),
    ]
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
