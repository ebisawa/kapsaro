// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::feature::inspect::verification::{
    build_online_verification_section, build_signature_verification_section,
    OnlineVerificationDisplay,
};
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
use crate::support::fs::load_text_with_limit;
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::runtime::block_on_result;
use crate::Result;

pub struct InspectCommand {
    pub input_display: String,
    pub output: InspectOutput,
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
    inspect_output
        .sections
        .push(build_signature_verification_section(&signature_report).into());

    if let Some(section) = build_online_section(options, &signature_report) {
        inspect_output.sections.push(section);
    }

    Ok(InspectCommand {
        input_display: format_path_relative_to_cwd(input_path),
        output: inspect_output,
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

fn build_online_section(
    options: &CommonCommandOptions,
    report: &SignatureVerificationReport,
) -> Option<InspectSection> {
    let public_key = report.signer_public_key.as_ref()?;
    if !report.verified {
        return None;
    }

    let binding_claims = public_key.protected.binding_claims.as_ref()?;
    let github = match binding_claims.github_account.as_ref() {
        Some(github) => github,
        None => {
            return Some(
                build_online_verification_section(
                    &OnlineVerificationDisplay::NoSupportedBinding,
                    None,
                    None,
                )
                .into(),
            );
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
    let verified_github = result.verified_github.clone();
    let github_login = verified_github
        .as_ref()
        .map(|verified| verified.login.as_str())
        .or(Some(github.login.as_str()));
    let github_id = verified_github
        .as_ref()
        .map(|verified| verified.id)
        .or(Some(github.id));
    Some(
        build_online_verification_section(
            &OnlineVerificationDisplay::GithubResult(result),
            github_login,
            github_id,
        )
        .into(),
    )
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
