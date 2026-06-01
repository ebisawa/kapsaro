// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! member verify command orchestration.
//! Resolves workspace member targets before delegating verification logic.

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::feature::member::verification::{
    append_verification_warnings, build_offline_verification_failure,
    derive_member_handle_from_path, has_github_claim, verify_member_public_key_file,
};
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::VerificationResult;
use crate::io::workspace::members::{get_active_member_file_path, list_active_member_paths};
use crate::support::display::sanitize_display_field;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::runtime::block_on;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

use super::types::MemberVerificationResult;
use super::view::build_member_verification_result;

pub fn verify_members(
    options: &CommonCommandOptions,
    member_handles: &[String],
    verbose: bool,
) -> Result<Vec<MemberVerificationResult>> {
    let workspace = require_workspace(options, "member verify")?;
    let member_files = select_verification_member_files(&workspace.root_path, member_handles)?;
    let results = block_on(verify_member_files(&member_files, verbose))?;
    Ok(results
        .into_iter()
        .map(build_member_verification_result)
        .collect())
}

pub(crate) async fn verify_member_files(
    member_files: &[PathBuf],
    verbose: bool,
) -> Vec<VerificationResult> {
    let mut results = Vec::new();
    for member_file in member_files {
        let subject = match build_verified_member_file_subject(member_file, verbose) {
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
                verbose,
            )
            .await,
        );
    }
    results
}

pub(crate) async fn verify_member_public_keys(
    public_keys: &[crate::model::public_key::PublicKey],
    verbose: bool,
) -> Result<Vec<VerificationResult>> {
    let mut results = Vec::new();
    for public_key in public_keys {
        let subject = match crate::feature::member::verification::verify_member_public_key(
            public_key, verbose,
        ) {
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
                verbose,
            )
            .await,
        );
    }
    Ok(results)
}

fn build_verified_member_file_subject(
    member_file: &Path,
    verbose: bool,
) -> Result<crate::feature::member::verification::VerifiedMemberFile> {
    let member_handle = derive_member_handle_from_path(member_file);
    let public_key = crate::io::workspace::members::load_member_file_from_path(member_file)?;
    let source_name = format_path_relative_to_cwd(member_file);
    verify_member_public_key_file(&public_key, Some(&member_handle), &source_name, verbose)
}

async fn verify_public_key_online(
    member_handle: &str,
    public_key: &crate::model::public_key::PublicKey,
    warnings: &[String],
    verbose: bool,
) -> VerificationResult {
    let result = match verify_github_account(public_key, verbose).await {
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
            let path = get_active_member_file_path(workspace_path, member_handle);
            path.exists().then_some(path).ok_or_else(|| {
                Error::build_not_found_error(format!(
                    "Member '{}' not found in active/",
                    sanitize_display_field(member_handle)
                ))
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_member_verification_test.rs"]
mod tests;
