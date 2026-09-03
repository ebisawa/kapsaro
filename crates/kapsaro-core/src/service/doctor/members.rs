// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Doctor checks for active and incoming member files in the workspace.
//! Validates each member file, its key expiry and GitHub binding, and checks kid uniqueness across members.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::feature::context::expiry::{check_key_expiry, KeyExpiryStatus};
use crate::feature::member::verification::{
    derive_member_handle_from_path, verify_member_public_key_file, VerifiedMemberFile,
};
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::io::workspace::members::{
    open_member_documents_at, MemberDocuments, MemberStatus, MEMBERS_DIR_NAME,
};
use crate::model::public_key::PublicKey;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::runtime::block_on_result;
use crate::Result;

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};

/// Diagnose the member documents the workspace holds.
///
/// Both status directories are listed through the descriptor this run bound to,
/// and every document is read relative to the directory its listing came from,
/// so the whole report describes one workspace even if the path that reached it
/// is repointed while the diagnosis runs.
pub fn check_members(workspace: &AnchoredDir) -> Result<Vec<DoctorCheck>> {
    let active = open_member_documents_at(workspace, MemberStatus::Active)?;
    let incoming = open_member_documents_at(workspace, MemberStatus::Incoming)?;

    let mut checks = check_active_members(&active);
    checks.extend(check_incoming_members(&incoming));
    checks.push(check_kid_uniqueness(&active, &incoming));
    Ok(checks)
}

fn check_active_members(documents: &MemberDocuments) -> Vec<DoctorCheck> {
    if documents.names().is_empty() {
        return vec![check_missing_active_members(documents.dir_path())];
    }

    let mut checks = vec![check_present_active_members(documents.names().len())];
    extend_member_document_checks(
        &mut checks,
        documents,
        "members.active.file",
        DoctorCategory::MembersActive,
    );
    checks
}

fn check_missing_active_members(active_dir: &Path) -> DoctorCheck {
    DoctorCheck::fail(
        "members.active.present",
        DoctorCategory::MembersActive,
        DoctorSubject::Path(format_path_relative_to_cwd(active_dir)),
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

fn check_incoming_members(documents: &MemberDocuments) -> Vec<DoctorCheck> {
    if documents.names().is_empty() {
        return vec![check_empty_incoming_members(documents.dir_path())];
    }

    let mut checks = vec![check_pending_incoming_members(documents.names().len())];
    extend_member_document_checks(
        &mut checks,
        documents,
        "members.incoming.file",
        DoctorCategory::MembersIncoming,
    );
    checks
}

fn check_empty_incoming_members(incoming_dir: &Path) -> DoctorCheck {
    DoctorCheck::ok(
        "members.incoming.empty",
        DoctorCategory::MembersIncoming,
        DoctorSubject::Path(format_path_relative_to_cwd(incoming_dir)),
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

fn extend_member_document_checks(
    checks: &mut Vec<DoctorCheck>,
    documents: &MemberDocuments,
    id: &'static str,
    category: DoctorCategory,
) {
    for name in documents.names() {
        checks.extend(verify_member_document(id, category, documents, name));
    }
}

fn verify_member_document(
    id: &'static str,
    category: DoctorCategory,
    documents: &MemberDocuments,
    name: &str,
) -> Vec<DoctorCheck> {
    let path = documents.document_path(name);
    let member_handle = derive_member_handle_from_path(&path);
    let public_key = match documents.load(name) {
        Ok(public_key) => public_key,
        Err(error) => {
            return vec![build_unloadable_member_check(
                id,
                category,
                &path,
                &member_handle,
                error.format_user_message(),
            )]
        }
    };

    match verify_member_public_key_file(
        &public_key,
        Some(&member_handle),
        &format_path_relative_to_cwd(&path),
    ) {
        Ok(verified) => build_verified_member_checks(id, category, &path, verified),
        Err(error) => vec![check_failed_member_verification(
            id,
            category,
            &path,
            error.format_user_message(),
        )],
    }
}

fn build_unloadable_member_check(
    id: &'static str,
    category: DoctorCategory,
    path: &Path,
    member_handle: &str,
    reason: &str,
) -> DoctorCheck {
    DoctorCheck::fail(
        id,
        category,
        DoctorSubject::Member(member_handle.to_string()),
        format!(
            "{} failed validation: {}",
            format_path_relative_to_cwd(path),
            reason
        ),
    )
}

fn build_verified_member_checks(
    id: &'static str,
    category: DoctorCategory,
    path: &Path,
    verified: VerifiedMemberFile,
) -> Vec<DoctorCheck> {
    let mut checks = vec![DoctorCheck::ok(
        id,
        category,
        DoctorSubject::Member(verified.member_handle.clone()),
        format!("{} is valid", format_path_relative_to_cwd(path)),
    )];
    checks.push(check_member_expiry(
        category,
        &verified.member_handle,
        path,
        &verified.public_key,
    ));
    checks.push(check_github_verification(
        category,
        &verified.member_handle,
        &verified.public_key,
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
    public_key: &PublicKey,
) -> DoctorCheck {
    if !has_github_binding(public_key) {
        return check_missing_github_binding(category, member_handle);
    }

    match block_on_result(verify_github_account(public_key)) {
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

fn has_github_binding(public_key: &PublicKey) -> bool {
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

/// Judge the expiry on the document the validation above already read, so the
/// finding describes the same document rather than whatever a second read of
/// the name would reach.
fn check_member_expiry(
    category: DoctorCategory,
    member_handle: &str,
    path: &Path,
    public_key: &PublicKey,
) -> DoctorCheck {
    let result = check_key_expiry(&public_key.protected.expires_at, OffsetDateTime::now_utc());
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

/// A document that will not load is left to the per-document checks above,
/// which report it under its own member: a kid that cannot be read conflicts
/// with nothing, and naming it twice would say the same failure twice.
fn check_kid_uniqueness(active: &MemberDocuments, incoming: &MemberDocuments) -> DoctorCheck {
    let mut seen: BTreeMap<String, PathBuf> = BTreeMap::new();
    for documents in [active, incoming] {
        for name in documents.names() {
            let Ok(public_key) = documents.load(name) else {
                continue;
            };
            let path = documents.document_path(name);
            let kid = public_key.protected.kid;
            if let Some(previous) = seen.insert(kid.clone(), path.clone()) {
                return check_duplicate_kid(kid, &previous, &path);
            }
        }
    }
    DoctorCheck::ok(
        "members.kid_unique",
        DoctorCategory::MembersActive,
        DoctorSubject::General(MEMBERS_DIR_NAME.to_string()),
        "Active and incoming member kids are unique",
    )
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
