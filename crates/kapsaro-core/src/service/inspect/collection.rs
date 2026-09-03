// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Collects inspect content and verification reports from lower layers.
//! Resolves optional online verification into typed metadata.

use std::path::Path;

use super::metadata::{build_online_verification_metadata, OnlineVerificationMetadata};
use super::OnlineVerificationDisplay;
use crate::feature::verify::file::verify_file_document_report;
use crate::feature::verify::kv::signature::verify_kv_document_report;
use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::EncContent;
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::model::public_key::GithubAccount;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::runtime::block_on_result;
use crate::Result;

struct GithubAccountDisplayValues {
    login: String,
    id: u64,
}

pub(super) fn load_inspect_content(input_path: &Path) -> Result<EncContent> {
    EncContent::detect_with_source(
        load_text_with_limit(
            input_path,
            resolve_encrypted_artifact_read_limit(input_path),
            "encrypted artifact",
        )?,
        input_path.display().to_string(),
    )
}

pub(super) fn build_signature_report(content: &EncContent) -> Result<SignatureVerificationReport> {
    Ok(match content {
        EncContent::FileEnc(file_content) => {
            let doc = file_content.parse()?;
            verify_file_document_report(&doc)
        }
        EncContent::KvEnc(kv_content) => verify_kv_document_report(kv_content.as_str()),
    })
}

pub(super) fn build_online_output(
    report: &SignatureVerificationReport,
) -> Option<OnlineVerificationMetadata> {
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
    let result = verify_online_github_account(public_key);
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
) -> VerificationResult {
    match block_on_result(verify_github_account(public_key)) {
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
) -> OnlineVerificationMetadata {
    build_online_verification_metadata(display, github_login, github_id)
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
