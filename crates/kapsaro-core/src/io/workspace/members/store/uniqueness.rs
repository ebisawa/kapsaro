// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::super::paths::{members_dir, MemberStatus};
use super::load::{
    load_json_file_names_in_dir_at, load_json_files_in_dir, load_verified_member_file_at,
    load_verified_member_file_from_path,
};
use super::save::member_status_dir_name;
use crate::support::fs::relative::DirectoryFd;
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct MemberKidCandidate {
    pub member_handle: String,
    pub kid: String,
    pub status: MemberStatus,
}

pub fn ensure_member_document_kid_is_unique(
    workspace_path: &Path,
    status: MemberStatus,
    member_handle: &str,
    kid: &str,
    allow_replace_self: bool,
) -> Result<()> {
    let ignored_existing = if allow_replace_self {
        vec![(status, member_handle.to_string())]
    } else {
        Vec::new()
    };
    let candidate = MemberKidCandidate {
        member_handle: member_handle.to_string(),
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
    let existing = load_member_kid_candidates(workspace_path, existing_statuses, ignored_existing)?;
    check_member_kid_candidates(&existing, candidates)
}

pub(crate) fn check_workspace_member_kid_uniqueness_in_open_dirs<A, I>(
    active_dir: &A,
    incoming_dir: &I,
    candidates: &[MemberKidCandidate],
    ignored_existing: &[(MemberStatus, String)],
) -> Result<()>
where
    A: DirectoryFd,
    I: DirectoryFd,
{
    let existing =
        load_member_kid_candidates_from_open_dirs(active_dir, incoming_dir, ignored_existing)?;
    check_member_kid_candidates(&existing, candidates)
}

fn check_member_kid_candidates(
    existing: &[MemberKidCandidate],
    candidates: &[MemberKidCandidate],
) -> Result<()> {
    let mut seen: BTreeMap<String, MemberKidCandidate> = BTreeMap::new();

    for existing in existing {
        if let Some(previous) = seen.insert(existing.kid.clone(), existing.clone()) {
            return Err(duplicate_kid_error(&previous, existing));
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

fn load_member_kid_candidates_from_open_dirs<A, I>(
    active_dir: &A,
    incoming_dir: &I,
    ignored_existing: &[(MemberStatus, String)],
) -> Result<Vec<MemberKidCandidate>>
where
    A: DirectoryFd,
    I: DirectoryFd,
{
    let mut candidates = Vec::new();
    candidates.extend(load_member_kid_candidates_from_open_dir(
        active_dir,
        MemberStatus::Active,
        ignored_existing,
    )?);
    candidates.extend(load_member_kid_candidates_from_open_dir(
        incoming_dir,
        MemberStatus::Incoming,
        ignored_existing,
    )?);
    Ok(candidates)
}

fn load_member_kid_candidates_from_open_dir<D>(
    dir: &D,
    status: MemberStatus,
    ignored_existing: &[(MemberStatus, String)],
) -> Result<Vec<MemberKidCandidate>>
where
    D: DirectoryFd,
{
    let mut candidates = Vec::new();
    for name in load_json_file_names_in_dir_at(dir)? {
        let Some(member_handle) = Path::new(&name)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(String::from)
        else {
            continue;
        };
        if is_ignored_existing(ignored_existing, status, &member_handle) {
            continue;
        }
        let member = load_verified_member_file_at(dir, &name)?;
        candidates.push(MemberKidCandidate {
            member_handle,
            kid: member.protected.kid.clone(),
            status,
        });
    }
    Ok(candidates)
}

fn load_member_kid_candidates(
    workspace_path: &Path,
    statuses: &[MemberStatus],
    ignored_existing: &[(MemberStatus, String)],
) -> Result<Vec<MemberKidCandidate>> {
    let mut candidates = Vec::new();
    for status in statuses {
        for path in load_json_files_in_dir(&members_dir(workspace_path, *status))? {
            let Some(member_handle) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(String::from)
            else {
                continue;
            };
            if is_ignored_existing(ignored_existing, *status, &member_handle) {
                continue;
            }
            let member = load_verified_member_file_from_path(&path)?;
            candidates.push(MemberKidCandidate {
                member_handle,
                kid: member.protected.kid.clone(),
                status: *status,
            });
        }
    }
    Ok(candidates)
}

fn is_ignored_existing(
    ignored_existing: &[(MemberStatus, String)],
    status: MemberStatus,
    member_handle: &str,
) -> bool {
    ignored_existing
        .iter()
        .any(|(ignored_status, ignored_member_handle)| {
            *ignored_status == status && ignored_member_handle == member_handle
        })
}

fn duplicate_kid_error(existing: &MemberKidCandidate, candidate: &MemberKidCandidate) -> Error {
    Error::build_config_error(format!(
        "Duplicate kid '{}' in workspace members: {}/'{}' conflicts with {}/'{}'",
        format_kid_display_lossy(&candidate.kid),
        member_status_dir_name(existing.status),
        existing.member_handle,
        member_status_dir_name(candidate.status),
        candidate.member_handle
    ))
}
