// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::super::paths::{members_dir, MemberStatus};
use super::load::{load_json_files_in_dir, load_verified_member_file_from_path};
use super::save::member_status_dir_name;
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct MemberKidCandidate {
    pub member_id: String,
    pub kid: String,
    pub status: MemberStatus,
}

pub fn ensure_member_document_kid_is_unique(
    workspace_path: &Path,
    status: MemberStatus,
    member_id: &str,
    kid: &str,
    allow_replace_self: bool,
) -> Result<()> {
    let ignored_existing = if allow_replace_self {
        vec![(status, member_id.to_string())]
    } else {
        Vec::new()
    };
    let candidate = MemberKidCandidate {
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        status,
    };
    check_workspace_member_kid_uniqueness(
        workspace_path,
        &[candidate],
        &ignored_existing,
        &[MemberStatus::Active, MemberStatus::Incoming],
    )
}

pub fn ensure_workspace_member_kid_uniqueness(workspace_path: &Path) -> Result<()> {
    check_workspace_member_kid_uniqueness(
        workspace_path,
        &[],
        &[],
        &[MemberStatus::Active, MemberStatus::Incoming],
    )
}

pub(crate) fn check_workspace_member_kid_uniqueness(
    workspace_path: &Path,
    candidates: &[MemberKidCandidate],
    ignored_existing: &[(MemberStatus, String)],
    existing_statuses: &[MemberStatus],
) -> Result<()> {
    let mut seen: BTreeMap<String, MemberKidCandidate> = BTreeMap::new();

    for existing in load_member_kid_candidates(workspace_path, existing_statuses, ignored_existing)?
    {
        if let Some(previous) = seen.insert(existing.kid.clone(), existing.clone()) {
            return Err(duplicate_kid_error(&previous, &existing));
        }
    }

    for candidate in candidates {
        if let Some(existing) = seen.get(&candidate.kid) {
            return Err(duplicate_kid_error(existing, candidate));
        }
        seen.insert(candidate.kid.clone(), candidate.clone());
    }

    Ok(())
}

fn load_member_kid_candidates(
    workspace_path: &Path,
    statuses: &[MemberStatus],
    ignored_existing: &[(MemberStatus, String)],
) -> Result<Vec<MemberKidCandidate>> {
    let mut candidates = Vec::new();
    for status in statuses {
        for path in load_json_files_in_dir(&members_dir(workspace_path, *status))? {
            let Some(member_id) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(String::from)
            else {
                continue;
            };
            if ignored_existing
                .iter()
                .any(|(ignored_status, ignored_member_id)| {
                    *ignored_status == *status && *ignored_member_id == member_id
                })
            {
                continue;
            }
            let member = load_verified_member_file_from_path(&path)?;
            candidates.push(MemberKidCandidate {
                member_id,
                kid: member.protected.kid.clone(),
                status: *status,
            });
        }
    }
    Ok(candidates)
}

fn duplicate_kid_error(existing: &MemberKidCandidate, candidate: &MemberKidCandidate) -> Error {
    Error::Config {
        message: format!(
            "Duplicate kid '{}' in workspace members: {}/'{}' conflicts with {}/'{}'",
            format_kid_display_lossy(&candidate.kid),
            member_status_dir_name(existing.status),
            existing.member_id,
            member_status_dir_name(candidate.status),
            candidate.member_id
        ),
    }
}
