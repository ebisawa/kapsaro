// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::feature::context::expiry::{check_key_expiry, KeyExpiryStatus};
use crate::feature::member::verification::verify_member_file;
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::VerificationStatus;
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
        checks.push(
            DoctorCheck::fail(
                "members.active.present",
                DoctorCategory::MembersActive,
                DoctorSubject::Path(format_path_relative_to_cwd(
                    &workspace_root.join("members/active"),
                )),
                "No active members found",
            )
            .with_next_action("run secretenv init or restore members/active"),
        );
        return Ok(checks);
    }

    checks.push(DoctorCheck::ok(
        "members.active.present",
        DoctorCategory::MembersActive,
        DoctorSubject::General("members/active".to_string()),
        format!("{} active member file(s) found", paths.len()),
    ));
    extend_member_path_checks(
        &mut checks,
        &paths,
        "members.active.file",
        DoctorCategory::MembersActive,
        verbose,
    );
    Ok(checks)
}

fn check_incoming_members(workspace_root: &Path, verbose: bool) -> Result<Vec<DoctorCheck>> {
    let paths = list_incoming_member_paths(workspace_root)?;
    let mut checks = Vec::new();
    if paths.is_empty() {
        checks.push(DoctorCheck::ok(
            "members.incoming.empty",
            DoctorCategory::MembersIncoming,
            DoctorSubject::Path(format_path_relative_to_cwd(
                &workspace_root.join("members/incoming"),
            )),
            "No incoming members",
        ));
        return Ok(checks);
    }

    checks.push(
        DoctorCheck::warn(
            "members.incoming.pending",
            DoctorCategory::MembersIncoming,
            DoctorSubject::General("members/incoming".to_string()),
            format!("{} incoming member file(s) pending", paths.len()),
        )
        .with_next_action("review the PR and run secretenv rewrap"),
    );
    extend_member_path_checks(
        &mut checks,
        &paths,
        "members.incoming.file",
        DoctorCategory::MembersIncoming,
        verbose,
    );
    Ok(checks)
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
    match verify_member_file(path, None, verbose) {
        Ok(verified) => {
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
        Err(error) => vec![DoctorCheck::fail(
            id,
            category,
            DoctorSubject::Path(format_path_relative_to_cwd(path)),
            "Member file verification failed",
        )
        .with_reason(error.format_user_message())
        .with_next_action("fix the member file and review the PR")],
    }
}

fn check_github_verification(
    category: DoctorCategory,
    member_handle: &str,
    public_key: &crate::model::public_key::PublicKey,
    verbose: bool,
) -> DoctorCheck {
    let has_binding = public_key
        .protected
        .binding_claims
        .as_ref()
        .and_then(|claims| claims.github_account.as_ref())
        .is_some();
    if !has_binding {
        return DoctorCheck::warn(
            "github.verify",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "GitHub binding is not configured",
        )
        .with_next_action("run secretenv member verify if manual review is needed");
    }

    match block_on_result(verify_github_account(public_key, verbose)) {
        Ok(result) if result.status == VerificationStatus::Verified => DoctorCheck::ok(
            "github.verify",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "GitHub account and SSH key match",
        ),
        Ok(result) if result.status == VerificationStatus::Failed => DoctorCheck::fail(
            "github.verify",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "GitHub verification failed",
        )
        .with_reason(result.message)
        .with_next_action("check the key owner and GitHub SSH keys"),
        Ok(result) => DoctorCheck::warn(
            "github.verify",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "GitHub verification is not configured",
        )
        .with_reason(result.message),
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

fn check_member_expiry(category: DoctorCategory, member_handle: &str, path: &Path) -> DoctorCheck {
    match load_member_file_from_path(path).and_then(|public_key| {
        check_key_expiry(&public_key.protected.expires_at, OffsetDateTime::now_utc())
    }) {
        Ok(KeyExpiryStatus::Valid) => DoctorCheck::ok(
            "key.expiry",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "Key has sufficient validity",
        ),
        Ok(KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        }) => DoctorCheck::warn(
            "key.expiry",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "Key expiry is near",
        )
        .with_reason(format!(
            "expires_at: {}; days remaining: {}",
            expires_at, days_remaining
        ))
        .with_next_action("plan key new, join, and rewrap"),
        Ok(KeyExpiryStatus::Expired { expires_at }) => DoctorCheck::fail(
            "key.expiry",
            category,
            DoctorSubject::Member(member_handle.to_string()),
            "Key is expired",
        )
        .with_reason(format!("expires_at: {}", expires_at))
        .with_next_action("rotate the key and run secretenv rewrap"),
        Err(error) => DoctorCheck::fail(
            "key.expiry",
            category,
            DoctorSubject::Path(format_path_relative_to_cwd(path)),
            "Key expiry could not be checked",
        )
        .with_reason(error.format_user_message()),
    }
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
            return Ok(DoctorCheck::fail(
                "members.kid_unique",
                DoctorCategory::MembersActive,
                DoctorSubject::General(kid),
                "Duplicate kid found in workspace members",
            )
            .with_reason(format!(
                "{} conflicts with {}",
                format_path_relative_to_cwd(&previous),
                format_path_relative_to_cwd(&path)
            ))
            .with_next_action("remove or reissue the conflicting member file"));
        }
    }
    Ok(DoctorCheck::ok(
        "members.kid_unique",
        DoctorCategory::MembersActive,
        DoctorSubject::General("members".to_string()),
        "Active and incoming member kids are unique",
    ))
}
