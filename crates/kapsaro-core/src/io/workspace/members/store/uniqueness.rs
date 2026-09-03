// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Uniqueness of the key identifiers the workspace members carry.
//! Reads every member document through its directory descriptor to find a kid claimed twice.

use super::super::paths::{status_dir_name, MemberStatus};
use super::load::{load_member_document_names_at, load_verified_member_file_at};
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

/// Judge one saved document's kid against the status directories the caller
/// already holds open.
///
/// A save runs this and its write under one lock on `members/`, so the member
/// set the kid was judged against is the set the document lands in.
pub(crate) fn ensure_member_document_kid_is_unique_in_open_dirs<A, I>(
    active_dir: &A,
    incoming_dir: &I,
    status: MemberStatus,
    member_handle: &str,
    kid: &str,
    allow_replace_self: bool,
) -> Result<()>
where
    A: DirectoryFd,
    I: DirectoryFd,
{
    let (candidate, ignored_existing) =
        build_saved_member_candidate(status, member_handle, kid, allow_replace_self);
    check_workspace_member_kid_uniqueness_in_open_dirs(
        active_dir,
        incoming_dir,
        &[candidate],
        &ignored_existing,
    )
}

/// The candidate one saved document offers, and the document it replaces.
///
/// A save that overwrites its own document must not collide with the version it
/// is replacing, so that one is left out of the existing set.
fn build_saved_member_candidate(
    status: MemberStatus,
    member_handle: &str,
    kid: &str,
    allow_replace_self: bool,
) -> (MemberKidCandidate, Vec<(MemberStatus, String)>) {
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
    (candidate, ignored_existing)
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
    for name in load_member_document_names_at(dir)? {
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
        status_dir_name(existing.status),
        existing.member_handle,
        status_dir_name(candidate.status),
        candidate.member_handle
    ))
}
