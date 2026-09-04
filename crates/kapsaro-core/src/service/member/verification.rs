// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! member verify command orchestration.
//! Resolves workspace member targets before delegating verification logic.

use crate::feature::member::verification::{
    append_verification_warnings, build_offline_verification_failure,
    derive_member_handle_from_path, has_github_claim, verify_member_public_key_file,
};
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::VerificationResult;
use crate::io::workspace::members::{get_active_member_file_path, list_active_member_paths};
use crate::model::identity::MemberHandle;
use crate::support::display::sanitize_display_field;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::runtime::block_on;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

use super::types::MemberVerificationResult;
use super::view::build_member_verification_result;

pub fn evaluate_members_online(
    workspace_path: &Path,
    member_handles: &[String],
) -> Result<Vec<MemberVerificationResult>> {
    let member_files = select_verification_member_files(workspace_path, member_handles)?;
    let results = block_on(verify_member_files(&member_files))?;
    Ok(results
        .into_iter()
        .map(build_member_verification_result)
        .collect())
}

pub(crate) async fn verify_member_files(member_files: &[PathBuf]) -> Vec<VerificationResult> {
    let mut results = Vec::new();
    for member_file in member_files {
        let subject = match build_verified_member_file_subject(member_file) {
            Ok(subject) => subject,
            Err(error) => {
                let member_handle = derive_member_handle_from_path(member_file);
                results.push(build_offline_verification_failure(
                    &member_handle,
                    error,
                    false,
                ));
                continue;
            }
        };
        results.push(
            verify_public_key_online(
                &subject.member_handle,
                &subject.public_key,
                &subject.warnings,
            )
            .await,
        );
    }
    results
}

pub(crate) async fn verify_member_public_keys(
    public_keys: &[crate::model::public_key::PublicKey],
) -> Result<Vec<VerificationResult>> {
    let mut results = Vec::new();
    for public_key in public_keys {
        let subject =
            match crate::feature::member::verification::verify_member_public_key(public_key) {
                Ok(subject) => subject,
                Err(error) => {
                    results.push(build_offline_verification_failure(
                        &public_key.protected.subject_handle,
                        error,
                        has_github_claim(public_key),
                    ));
                    continue;
                }
            };
        results.push(
            verify_public_key_online(
                &subject.member_handle,
                &subject.public_key,
                &subject.warnings,
            )
            .await,
        );
    }
    Ok(results)
}

fn build_verified_member_file_subject(
    member_file: &Path,
) -> Result<crate::feature::member::verification::VerifiedMemberFile> {
    let member_handle = derive_member_handle_from_path(member_file);
    let public_key = crate::io::workspace::members::load_member_file_from_path(member_file)?;
    let source_name = format_path_relative_to_cwd(member_file);
    verify_member_public_key_file(&public_key, Some(&member_handle), &source_name)
}

async fn verify_public_key_online(
    member_handle: &str,
    public_key: &crate::model::public_key::PublicKey,
    warnings: &[String],
) -> VerificationResult {
    let result = match verify_github_account(public_key).await {
        Ok(result) => result,
        Err(error) => VerificationResult::failed(
            member_handle,
            format!("Online verification error: {}", error.format_user_message()),
            None,
            has_github_claim(public_key),
        ),
    };

    append_verification_warnings(result, warnings)
}

fn select_verification_member_files(
    workspace_path: &Path,
    member_handles: &[String],
) -> Result<Vec<PathBuf>> {
    if member_handles.is_empty() {
        return list_active_member_paths(workspace_path);
    }

    member_handles
        .iter()
        .map(|member_handle| {
            // The handle names one entry of members/active, so it is validated
            // as a handle before it is joined onto that directory.
            let member_handle = MemberHandle::try_from(member_handle.as_str())?;
            let path = get_active_member_file_path(workspace_path, member_handle.as_str());
            path.exists().then_some(path).ok_or_else(|| {
                Error::build_not_found_error(format!(
                    "Member '{}' not found in active/",
                    sanitize_display_field(member_handle.as_str())
                ))
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_member_verification_test.rs"]
mod service_member_verification_test;
