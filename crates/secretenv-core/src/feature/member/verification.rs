// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member verification - online verification of member binding claims.

use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, MEMBER_VERIFICATION_INPUT_CONTEXT,
    WORKSPACE_MEMBER_FILE_CONTEXT,
};
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::io::workspace::members::load_member_file_from_path;
use crate::model::public_key::PublicKey;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

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

pub fn verify_member_file(
    member_file: &Path,
    expected_member_handle: Option<&str>,
    debug: bool,
) -> Result<VerifiedMemberFile> {
    load_verified_member_subject_from_file(member_file, expected_member_handle, debug)
        .map(Into::into)
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

fn load_verified_member_subject_from_file(
    member_file: &Path,
    expected_member_handle: Option<&str>,
    debug: bool,
) -> Result<VerifiedMemberSubject> {
    let fallback_member_handle = expected_member_handle
        .map(str::to_string)
        .unwrap_or_else(|| derive_member_handle_from_path(member_file));
    let public_key = load_member_file_from_path(member_file)?;

    validate_member_file_member_handle(member_file, &fallback_member_handle, &public_key)?;
    let verified = verify_public_key_for_verification_context(
        &public_key,
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
        public_key,
        verified.warnings,
    ))
}

fn validate_member_file_member_handle(
    member_file: &Path,
    expected_member_handle: &str,
    public_key: &PublicKey,
) -> Result<()> {
    if public_key.protected.subject_handle == expected_member_handle {
        return Ok(());
    }

    Err(Error::build_invalid_argument_error(format!(
        "Member handle mismatch in {}: expected '{}', found '{}'",
        format_path_relative_to_cwd(member_file),
        expected_member_handle,
        public_key.protected.subject_handle
    )))
}

pub fn derive_member_handle_from_path(member_file: &Path) -> String {
    member_file
        .file_stem()
        .and_then(OsStr::to_str)
        .map(str::to_string)
        .unwrap_or_else(|| format_path_relative_to_cwd(member_file))
}

pub async fn verify_member_public_keys(
    public_keys: &[PublicKey],
    verbose: bool,
) -> Result<Vec<VerificationResult>> {
    verify_public_key_candidates(public_keys, verbose).await
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

/// Verify member files' binding_claims via GitHub online verification.
///
/// Offline verification failures, network errors, and API failures are converted
/// to `VerificationResult::failed` rather than propagated as `Err`.
pub async fn verify_member_files(
    member_files: &[PathBuf],
    verbose: bool,
) -> Vec<VerificationResult> {
    verify_verified_member_subjects(
        member_files,
        verbose,
        |member_file, verbose| build_verified_member_subject_from_member_file(member_file, verbose),
        |member_file, error| build_member_file_offline_verification_failure(member_file, error),
    )
    .await
}

fn build_verified_member_subject_from_member_file(
    member_file: &Path,
    verbose: bool,
) -> Result<VerifiedMemberSubject> {
    let member_handle = derive_member_handle_from_path(member_file);
    load_verified_member_subject_from_file(member_file, Some(&member_handle), verbose)
}

fn build_member_file_offline_verification_failure(
    member_file: &Path,
    error: Error,
) -> VerificationResult {
    let member_handle = derive_member_handle_from_path(member_file);
    build_offline_verification_failure(&member_handle, error, false)
}

async fn verify_public_key_candidates(
    public_keys: &[PublicKey],
    verbose: bool,
) -> Result<Vec<VerificationResult>> {
    Ok(verify_verified_member_subjects(
        public_keys,
        verbose,
        build_verified_member_subject_from_public_key,
        |public_key, error| {
            build_offline_verification_failure(
                &public_key.protected.subject_handle,
                error,
                has_github_claim(public_key),
            )
        },
    )
    .await)
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

async fn verify_verified_member_subjects<T, Build, Failure>(
    items: &[T],
    verbose: bool,
    mut build_subject: Build,
    mut build_failure: Failure,
) -> Vec<VerificationResult>
where
    Build: FnMut(&T, bool) -> Result<VerifiedMemberSubject>,
    Failure: FnMut(&T, Error) -> VerificationResult,
{
    let mut results = Vec::new();
    for item in items {
        let subject = match build_subject(item, verbose) {
            Ok(subject) => subject,
            Err(error) => {
                results.push(build_failure(item, error));
                continue;
            }
        };
        results.push(verify_member_subject_online(&subject, verbose).await);
    }
    results
}

async fn verify_member_subject_online(
    subject: &VerifiedMemberSubject,
    verbose: bool,
) -> VerificationResult {
    let result = match verify_github_account(&subject.public_key, verbose).await {
        Ok(result) => result,
        Err(e) => VerificationResult::failed(
            &subject.member_handle,
            format!("Online verification error: {}", e.format_user_message()),
            None,
            has_github_claim(&subject.public_key),
        ),
    };

    append_verification_warnings(result, &subject.warnings)
}

fn append_verification_warnings(
    mut result: VerificationResult,
    warnings: &[String],
) -> VerificationResult {
    if warnings.is_empty() {
        return result;
    }

    result.message = format!("{} [{}]", result.message, warnings.join("; "));
    result
}

fn build_offline_verification_failure(
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

fn has_github_claim(public_key: &PublicKey) -> bool {
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
