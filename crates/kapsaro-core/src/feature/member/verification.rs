// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member verification - offline PublicKey validation and result grouping.

use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, MEMBER_VERIFICATION_INPUT_CONTEXT,
    WORKSPACE_MEMBER_FILE_CONTEXT,
};
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::model::public_key::PublicKey;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::ffi::OsStr;
use std::path::Path;

#[derive(Debug, Clone)]
struct VerifiedMemberSubject {
    member_handle: String,
    public_key: PublicKey,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedMemberFile {
    pub member_handle: String,
    pub public_key: PublicKey,
    pub warnings: Vec<String>,
}

pub fn verify_member_public_key_file(
    public_key: &PublicKey,
    expected_member_handle: Option<&str>,
    source_name: &str,
    debug: bool,
) -> Result<VerifiedMemberFile> {
    build_verified_member_subject_for_workspace_file(
        public_key,
        expected_member_handle,
        source_name,
        debug,
    )
    .map(Into::into)
}

pub fn verify_member_public_key(public_key: &PublicKey, debug: bool) -> Result<VerifiedMemberFile> {
    build_verified_member_subject_for_input(public_key, debug).map(Into::into)
}

impl From<VerifiedMemberSubject> for VerifiedMemberFile {
    fn from(subject: VerifiedMemberSubject) -> Self {
        Self {
            member_handle: subject.member_handle,
            public_key: subject.public_key,
            warnings: subject.warnings,
        }
    }
}

impl VerifiedMemberSubject {
    fn new(member_handle: String, public_key: PublicKey, warnings: Vec<String>) -> Self {
        Self {
            member_handle,
            public_key,
            warnings,
        }
    }
}

fn build_verified_member_subject_for_workspace_file(
    public_key: &PublicKey,
    expected_member_handle: Option<&str>,
    source_name: &str,
    debug: bool,
) -> Result<VerifiedMemberSubject> {
    let fallback_member_handle = expected_member_handle
        .map(str::to_string)
        .unwrap_or_else(|| source_name.to_string());

    validate_member_file_member_handle(source_name, &fallback_member_handle, public_key)?;
    let verified = verify_public_key_for_verification_context(
        public_key,
        debug,
        WORKSPACE_MEMBER_FILE_CONTEXT,
    )?;
    Ok(VerifiedMemberSubject::new(
        verified
            .verified_public_key
            .document()
            .protected
            .subject_handle
            .clone(),
        public_key.clone(),
        verified.warnings,
    ))
}

fn validate_member_file_member_handle(
    source_name: &str,
    expected_member_handle: &str,
    public_key: &PublicKey,
) -> Result<()> {
    if public_key.protected.subject_handle == expected_member_handle {
        return Ok(());
    }

    Err(Error::build_invalid_argument_error(format!(
        "Member handle mismatch in {}: expected '{}', found '{}'",
        source_name, expected_member_handle, public_key.protected.subject_handle
    )))
}

pub fn derive_member_handle_from_path(member_file: &Path) -> String {
    member_file
        .file_stem()
        .and_then(OsStr::to_str)
        .map(str::to_string)
        .unwrap_or_else(|| format_path_relative_to_cwd(member_file))
}

/// Classify verification results into verified, failed, and not_configured.
pub fn build_verification_result_groups(
    results: &[VerificationResult],
) -> (
    Vec<&VerificationResult>,
    Vec<&VerificationResult>,
    Vec<&VerificationResult>,
) {
    let mut verified = Vec::new();
    let mut failed = Vec::new();
    let mut not_configured = Vec::new();
    for result in results {
        match result.status {
            VerificationStatus::Verified => verified.push(result),
            VerificationStatus::Failed => failed.push(result),
            VerificationStatus::NotConfigured => not_configured.push(result),
        }
    }
    (verified, failed, not_configured)
}

fn build_verified_member_subject_from_public_key(
    public_key: &PublicKey,
    verbose: bool,
) -> Result<VerifiedMemberSubject> {
    let verified = verify_public_key_for_verification_context(
        public_key,
        verbose,
        MEMBER_VERIFICATION_INPUT_CONTEXT,
    )?;
    Ok(VerifiedMemberSubject::new(
        public_key.protected.subject_handle.clone(),
        public_key.clone(),
        verified.warnings,
    ))
}

fn build_verified_member_subject_for_input(
    public_key: &PublicKey,
    verbose: bool,
) -> Result<VerifiedMemberSubject> {
    build_verified_member_subject_from_public_key(public_key, verbose)
}

pub(crate) fn append_verification_warnings(
    mut result: VerificationResult,
    warnings: &[String],
) -> VerificationResult {
    if warnings.is_empty() {
        return result;
    }

    result.message = format!("{} [{}]", result.message, warnings.join("; "));
    result
}

pub(crate) fn build_offline_verification_failure(
    member_handle: &str,
    error: Error,
    github_claim_present: bool,
) -> VerificationResult {
    VerificationResult::failed(
        member_handle,
        format!(
            "Offline verification failed: {}",
            error.format_user_message()
        ),
        None,
        github_claim_present,
    )
}

pub(crate) fn has_github_claim(public_key: &PublicKey) -> bool {
    public_key
        .protected
        .binding_claims
        .as_ref()
        .and_then(|claims| claims.github_account.as_ref())
        .is_some()
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_member_verification_test.rs"]
mod tests;
