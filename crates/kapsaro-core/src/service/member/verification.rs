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
use crate::io::workspace::members::{open_member_documents_at, MemberDocuments, MemberStatus};
use crate::model::identity::MemberHandle;
use crate::service::workspace::WorkspaceAccess;
use crate::support::display::sanitize_display_field;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::runtime::block_on;
use crate::{Error, Result};
#[cfg(any(test, feature = "cli-test-support"))]
use std::path::{Path, PathBuf};

use super::types::MemberVerificationResult;
use super::view::build_member_verification_result;

pub fn evaluate_members_online(
    workspace: &WorkspaceAccess,
    member_handles: &[String],
) -> Result<Vec<MemberVerificationResult>> {
    let documents = open_member_documents_at(workspace.directory(), MemberStatus::Active)?;
    let names = select_verification_member_names(documents.names(), member_handles)?;
    let results = block_on(async {
        let mut results = Vec::new();
        for name in names {
            results.push(verify_workspace_member_online(&documents, &name).await);
        }
        results
    })?;
    Ok(results
        .into_iter()
        .map(build_member_verification_result)
        .collect())
}

async fn verify_workspace_member_online(
    documents: &MemberDocuments,
    name: &str,
) -> VerificationResult {
    let path = documents.document_path(name);
    let handle = derive_member_handle_from_path(&path);
    let subject = documents.load(name).and_then(|key| {
        verify_member_public_key_file(&key, Some(&handle), &format_path_relative_to_cwd(&path))
    });
    match subject {
        Ok(subject) => {
            verify_public_key_online(
                &subject.member_handle,
                &subject.public_key,
                &subject.warnings,
            )
            .await
        }
        Err(error) => build_offline_verification_failure(&handle, error, false),
    }
}

#[cfg(any(test, feature = "cli-test-support"))]
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

#[cfg(any(test, feature = "cli-test-support"))]
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

fn select_verification_member_names(
    names: &[String],
    member_handles: &[String],
) -> Result<Vec<String>> {
    if member_handles.is_empty() {
        return Ok(names.to_vec());
    }

    member_handles
        .iter()
        .map(|member_handle| {
            // The handle names one entry of members/active, so it is validated
            // as a handle before it is joined onto that directory.
            let member_handle = MemberHandle::try_from(member_handle.as_str())?;
            let name = format!("{member_handle}.json");
            names.contains(&name).then_some(name).ok_or_else(|| {
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
