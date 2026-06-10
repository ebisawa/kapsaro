// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::feature::context::expiry::{check_key_expiry, KeyExpiryStatus};
use crate::feature::member::verification::{
    derive_member_handle_from_path, verify_member_public_key_file, VerifiedMemberFile,
};
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::io::workspace::detection::WorkspaceRoot;
use crate::io::workspace::members::{
    list_active_member_paths, list_incoming_member_paths, load_member_file_from_path,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::support::runtime::block_on_result;
use crate::Result;

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};

pub fn check_members(workspace: &WorkspaceRoot, verbose: bool) -> Result<Vec<DoctorCheck>> {
    let mut checks = Vec::new();
    checks.extend(check_active_members(&workspace.root_path, verbose)?);
    checks.extend(check_incoming_members(&workspace.root_path, verbose)?);
    checks.push(check_kid_uniqueness(&workspace.root_path)?);
    Ok(checks)
}

fn check_active_members(workspace_root: &Path, verbose: bool) -> Result<Vec<DoctorCheck>> {
    let paths = list_active_member_paths(workspace_root)?;
    let mut checks = Vec::new();
    if paths.is_empty() {
        checks.push(check_missing_active_members(workspace_root));
        return Ok(checks);
    }

    checks.push(check_present_active_members(paths.len()));
    extend_member_path_checks(
        &mut checks,
        &paths,
        "members.active.file",
        DoctorCategory::MembersActive,
        verbose,
    );
    Ok(checks)
}

fn check_missing_active_members(workspace_root: &Path) -> DoctorCheck {
    DoctorCheck::fail(
        "members.active.present",
        DoctorCategory::MembersActive,
        DoctorSubject::Path(format_path_relative_to_cwd(
            &workspace_root.join("members/active"),
        )),
        "No active members found",
    )
    .with_next_action("run kapsaro init or restore members/active")
}

fn check_present_active_members(count: usize) -> DoctorCheck {
    DoctorCheck::ok(
        "members.active.present",
        DoctorCategory::MembersActive,
        DoctorSubject::General("members/active".to_string()),
        format!("{} active member file(s) found", count),
    )
}

fn check_incoming_members(workspace_root: &Path, verbose: bool) -> Result<Vec<DoctorCheck>> {
    let paths = list_incoming_member_paths(workspace_root)?;
    let mut checks = Vec::new();
    if paths.is_empty() {
        checks.push(check_empty_incoming_members(workspace_root));
        return Ok(checks);
    }

    checks.push(check_pending_incoming_members(paths.len()));
    extend_member_path_checks(
        &mut checks,
        &paths,
        "members.incoming.file",
        DoctorCategory::MembersIncoming,
        verbose,
    );
    Ok(checks)
}

fn check_empty_incoming_members(workspace_root: &Path) -> DoctorCheck {
    DoctorCheck::ok(
        "members.incoming.empty",
        DoctorCategory::MembersIncoming,
        DoctorSubject::Path(format_path_relative_to_cwd(
            &workspace_root.join("members/incoming"),
        )),
        "No incoming members",
    )
}

fn check_pending_incoming_members(count: usize) -> DoctorCheck {
    DoctorCheck::warn_with_next_action(
        "members.incoming.pending",
        DoctorCategory::MembersIncoming,
        DoctorSubject::General("members/incoming".to_string()),
        format!("{} incoming member file(s) pending", count),
        "review the PR and run kapsaro rewrap",
    )
}

fn extend_member_path_checks(
    checks: &mut Vec<DoctorCheck>,
    paths: &[PathBuf],
    id: &'static str,
    category: DoctorCategory,
    verbose: bool,
) {
    for path in paths {
        checks.extend(verify_member_path(id, category, path, verbose));
    }
}

fn verify_member_path(
    id: &'static str,
    category: DoctorCategory,
    path: &Path,
    verbose: bool,
) -> Vec<DoctorCheck> {
    let member_handle = derive_member_handle_from_path(path);
    let public_key = match load_member_file_for_doctor(id, category, path, &member_handle) {
        MemberFileCheck::Loaded(public_key) => public_key,
        MemberFileCheck::Finding(check) => return vec![check],
    };

    match verify_member_public_key_file(
        &public_key,
        Some(&member_handle),
        &format_path_relative_to_cwd(path),
        verbose,
    ) {
        Ok(verified) => build_verified_member_path_checks(id, category, path, verified, verbose),
        Err(error) => vec![check_failed_member_verification(
            id,
            category,
            path,
            error.format_user_message(),
        )],
    }
}

enum MemberFileCheck {
    Loaded(Box<crate::model::public_key::PublicKey>),
    Finding(DoctorCheck),
}

fn load_member_file_for_doctor(
    id: &'static str,
    category: DoctorCategory,
    path: &Path,
    member_handle: &str,
) -> MemberFileCheck {
    match load_member_file_from_path(path) {
        Ok(public_key) => MemberFileCheck::Loaded(Box::new(public_key)),
        Err(error) => MemberFileCheck::Finding(DoctorCheck::fail(
            id,
            category,
            DoctorSubject::Member(member_handle.to_string()),
            format!(
                "{} failed validation: {}",
                format_path_relative_to_cwd(path),
                error.format_user_message()
            ),
        )),
    }
}

fn build_verified_member_path_checks(
    id: &'static str,
    category: DoctorCategory,
    path: &Path,
    verified: VerifiedMemberFile,
    verbose: bool,
) -> Vec<DoctorCheck> {
    let mut checks = vec![DoctorCheck::ok(
        id,
        category,
        DoctorSubject::Member(verified.member_handle.clone()),
        format!("{} is valid", format_path_relative_to_cwd(path)),
    )];
    checks.push(check_member_expiry(category, &verified.member_handle, path));
    checks.push(check_github_verification(
        category,
        &verified.member_handle,
        &verified.public_key,
        verbose,
    ));
    checks
}

fn check_failed_member_verification(
    id: &'static str,
    category: DoctorCategory,
    path: &Path,
    reason: impl Into<String>,
) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        id,
        category,
        DoctorSubject::Path(format_path_relative_to_cwd(path)),
        "Member file verification failed",
        reason,
        "fix the member file and review the PR",
    )
}

fn check_github_verification(
    category: DoctorCategory,
    member_handle: &str,
    public_key: &crate::model::public_key::PublicKey,
    verbose: bool,
) -> DoctorCheck {
    if !has_github_binding(public_key) {
        return check_missing_github_binding(category, member_handle);
    }

    match block_on_result(verify_github_account(public_key, verbose)) {
        Ok(result) => check_github_result(category, member_handle, result),
        Err(error) => DoctorCheck::skip(
            "github.verify",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "GitHub verification was not completed",
        )
        .with_reason(error.format_user_message())
        .with_next_action("retry doctor later if online verification is required"),
    }
}

fn has_github_binding(public_key: &crate::model::public_key::PublicKey) -> bool {
    public_key
        .protected
        .binding_claims
        .as_ref()
        .and_then(|claims| claims.github_account.as_ref())
        .is_some()
}

fn check_missing_github_binding(category: DoctorCategory, member_handle: &str) -> DoctorCheck {
    DoctorCheck::warn_with_next_action(
        "github.verify",
        category,
        DoctorSubject::Member(member_handle.to_string()),
        "GitHub binding is not configured",
        "run kapsaro member verify if manual review is needed",
    )
}

fn check_github_result(
    category: DoctorCategory,
    member_handle: &str,
    result: VerificationResult,
) -> DoctorCheck {
    match result.status {
        VerificationStatus::Verified => DoctorCheck::ok(
            "github.verify",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "GitHub account and SSH key match",
        ),
        VerificationStatus::Failed => DoctorCheck::fail_with_reason_and_next_action(
            "github.verify",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "GitHub verification failed",
            result.message,
            "check the key owner and GitHub SSH keys",
        ),
        VerificationStatus::NotConfigured => DoctorCheck::warn(
            "github.verify",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "GitHub verification is not configured",
        )
        .with_reason(result.message),
    }
}

fn check_member_expiry(category: DoctorCategory, member_handle: &str, path: &Path) -> DoctorCheck {
    let result = load_member_file_from_path(path).and_then(|public_key| {
        check_key_expiry(&public_key.protected.expires_at, OffsetDateTime::now_utc())
    });
    build_member_expiry_check(category, member_handle, path, result)
}

fn build_member_expiry_check(
    category: DoctorCategory,
    member_handle: &str,
    path: &Path,
    result: Result<KeyExpiryStatus>,
) -> DoctorCheck {
    match result {
        Ok(KeyExpiryStatus::Valid) => build_valid_member_expiry_check(category, member_handle),
        Ok(KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        }) => build_expiring_member_check(category, member_handle, expires_at, days_remaining),
        Ok(KeyExpiryStatus::Expired { expires_at }) => {
            build_expired_member_check(category, member_handle, expires_at)
        }
        Err(error) => DoctorCheck::fail_with_reason(
            "key.expiry",
            category,
            DoctorSubject::Path(format_path_relative_to_cwd(path)),
            "Key expiry could not be checked",
            error.format_user_message(),
        ),
    }
}

fn build_valid_member_expiry_check(category: DoctorCategory, member_handle: &str) -> DoctorCheck {
    DoctorCheck::ok(
        "key.expiry",
        category,
        DoctorSubject::Member(member_handle.to_string()),
        "Key has sufficient validity",
    )
}

fn build_expiring_member_check(
    category: DoctorCategory,
    member_handle: &str,
    expires_at: String,
    days_remaining: i64,
) -> DoctorCheck {
    DoctorCheck::warn_with_reason_and_next_action(
        "key.expiry",
        category,
        DoctorSubject::Member(member_handle.to_string()),
        "Key expiry is near",
        format!(
            "expires_at: {}; days remaining: {}",
            expires_at, days_remaining
        ),
        "plan key new, join, and rewrap",
    )
}

fn build_expired_member_check(
    category: DoctorCategory,
    member_handle: &str,
    expires_at: String,
) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "key.expiry",
        category,
        DoctorSubject::Member(member_handle.to_string()),
        "Key is expired",
        format!("expires_at: {}", expires_at),
        "rotate the key and run kapsaro rewrap",
    )
}

fn check_kid_uniqueness(workspace_root: &Path) -> Result<DoctorCheck> {
    let mut seen: BTreeMap<String, PathBuf> = BTreeMap::new();
    for path in list_active_member_paths(workspace_root)?
        .into_iter()
        .chain(list_incoming_member_paths(workspace_root)?)
    {
        let Ok(public_key) = load_member_file_from_path(&path) else {
            continue;
        };
        let kid = public_key.protected.kid.clone();
        if let Some(previous) = seen.insert(kid.clone(), path.clone()) {
            return Ok(check_duplicate_kid(kid, &previous, &path));
        }
    }
    Ok(DoctorCheck::ok(
        "members.kid_unique",
        DoctorCategory::MembersActive,
        DoctorSubject::General("members".to_string()),
        "Active and incoming member kids are unique",
    ))
}

fn check_duplicate_kid(kid: String, previous: &Path, path: &Path) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "members.kid_unique",
        DoctorCategory::MembersActive,
        DoctorSubject::General(kid),
        "Duplicate kid found in workspace members",
        format!(
            "{} conflicts with {}",
            format_path_relative_to_cwd(previous),
            format_path_relative_to_cwd(path)
        ),
        "remove or reissue the conflicting member file",
    )
}
