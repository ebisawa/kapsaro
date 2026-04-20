// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member verification - online verification of member binding claims.

use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, MEMBER_VERIFICATION_INPUT_CONTEXT,
    WORKSPACE_MEMBER_FILE_CONTEXT,
};
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::io::workspace::members::{
    active_member_file_path, list_active_member_paths, load_member_file_from_path,
};
use crate::model::public_key::PublicKey;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::ffi::OsStr;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct VerifiedMemberFile {
    pub member_id: String,
    pub public_key: PublicKey,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct VerifiedMemberCandidate {
    member_id: String,
    public_key: PublicKey,
    warnings: Vec<String>,
}

pub fn load_and_verify_member_file(
    member_file: &Path,
    expected_member_id: Option<&str>,
    debug: bool,
) -> Result<VerifiedMemberFile> {
    let fallback_member_id = expected_member_id
        .map(str::to_string)
        .unwrap_or_else(|| member_id_from_path(member_file));
    let public_key = load_member_file_from_path(member_file)?;

    if public_key.protected.member_id != fallback_member_id {
        return Err(Error::InvalidArgument {
            message: format!(
                "Member handle mismatch in {}: expected '{}', found '{}'",
                display_path_relative_to_cwd(member_file),
                fallback_member_id,
                public_key.protected.member_id
            ),
        });
    }

    let verified = verify_public_key_for_verification_context(
        &public_key,
        debug,
        WORKSPACE_MEMBER_FILE_CONTEXT,
    )?;
    Ok(VerifiedMemberFile {
        member_id: verified
            .verified_public_key
            .document
            .protected
            .member_id
            .clone(),
        public_key,
        warnings: verified.warnings,
    })
}

pub fn member_id_from_path(member_file: &Path) -> String {
    member_file
        .file_stem()
        .and_then(OsStr::to_str)
        .map(str::to_string)
        .unwrap_or_else(|| display_path_relative_to_cwd(member_file))
}

/// Verify binding_claims.github_account for members (GitHub).
pub async fn verify_member(
    workspace_path: &Path,
    member_ids: &[String],
    verbose: bool,
) -> Result<Vec<VerificationResult>> {
    let member_files = list_verifiable_member_files(workspace_path, member_ids)?;
    Ok(verify_member_files(&member_files, verbose).await)
}

pub async fn verify_member_public_keys(
    public_keys: &[PublicKey],
    verbose: bool,
) -> Result<Vec<VerificationResult>> {
    verify_public_key_candidates(public_keys, verbose).await
}

/// Classify verification results into verified, failed, and not_configured.
pub fn classify_verification_results(
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
    member_files: &[std::path::PathBuf],
    verbose: bool,
) -> Vec<VerificationResult> {
    let mut results = Vec::new();
    for member_file in member_files {
        let result = verify_member_file_path(member_file, verbose).await;
        results.push(result);
    }
    results
}

async fn verify_member_file_path(member_file: &Path, verbose: bool) -> VerificationResult {
    let fallback_member_id = member_id_from_path(member_file);
    let candidate = match build_verified_candidate_from_file(member_file, verbose) {
        Ok(candidate) => candidate,
        Err(e) => return build_offline_verification_failure(&fallback_member_id, e, false),
    };
    verify_verified_candidate_online(&candidate, verbose).await
}

async fn verify_public_key_candidates(
    public_keys: &[PublicKey],
    verbose: bool,
) -> Result<Vec<VerificationResult>> {
    let mut results = Vec::new();
    for public_key in public_keys {
        let candidate = match build_verified_candidate_from_public_key(public_key, verbose) {
            Ok(candidate) => candidate,
            Err(e) => {
                results.push(build_offline_verification_failure(
                    &public_key.protected.member_id,
                    e,
                    has_github_claim(public_key),
                ));
                continue;
            }
        };
        results.push(verify_verified_candidate_online(&candidate, verbose).await);
    }
    Ok(results)
}

fn build_verified_candidate_from_file(
    member_file: &Path,
    verbose: bool,
) -> Result<VerifiedMemberCandidate> {
    let verified = load_and_verify_member_file(
        member_file,
        Some(&member_id_from_path(member_file)),
        verbose,
    )?;
    Ok(VerifiedMemberCandidate {
        member_id: verified.member_id,
        public_key: verified.public_key,
        warnings: verified.warnings,
    })
}

fn build_verified_candidate_from_public_key(
    public_key: &PublicKey,
    verbose: bool,
) -> Result<VerifiedMemberCandidate> {
    let verified = verify_public_key_for_verification_context(
        public_key,
        verbose,
        MEMBER_VERIFICATION_INPUT_CONTEXT,
    )?;
    Ok(VerifiedMemberCandidate {
        member_id: public_key.protected.member_id.clone(),
        public_key: public_key.clone(),
        warnings: verified.warnings,
    })
}

async fn verify_verified_candidate_online(
    candidate: &VerifiedMemberCandidate,
    verbose: bool,
) -> VerificationResult {
    let result = match verify_github_account(&candidate.public_key, verbose, None).await {
        Ok(result) => result,
        Err(e) => VerificationResult::failed(
            &candidate.member_id,
            format!("Online verification error: {}", e.user_message()),
            None,
            has_github_claim(&candidate.public_key),
        ),
    };

    append_verification_warnings(result, &candidate.warnings)
}

fn list_verifiable_member_files(
    workspace_path: &Path,
    member_ids: &[String],
) -> Result<Vec<std::path::PathBuf>> {
    if member_ids.is_empty() {
        return list_active_member_paths(workspace_path);
    }

    member_ids
        .iter()
        .map(|member_id| {
            let path = active_member_file_path(workspace_path, member_id);
            path.exists()
                .then_some(path)
                .ok_or_else(|| Error::NotFound {
                    message: format!("Member '{}' not found in active/", member_id),
                })
        })
        .collect()
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
    member_id: &str,
    error: Error,
    github_claim_present: bool,
) -> VerificationResult {
    VerificationResult::failed(
        member_id,
        format!("Offline verification failed: {}", error.user_message()),
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
#[path = "../../../tests/unit/feature_member_verification_test.rs"]
mod tests;
