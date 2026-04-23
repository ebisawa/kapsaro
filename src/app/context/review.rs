// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared review snapshot guards for app-layer commands.

use crate::app::trust::WorkspaceMemberSnapshot;
use crate::model::identity::{Kid, MemberId};
use crate::model::public_key::PublicKey;
use crate::support::fs;
use crate::{Error, Result};
use std::path::Path;

pub(crate) fn ensure_workspace_members_match_snapshot(
    workspace_root: &Path,
    reviewed_members: &WorkspaceMemberSnapshot,
    verbose: bool,
    mismatch_message: &str,
) -> Result<()> {
    let current_members = WorkspaceMemberSnapshot::load(workspace_root, verbose)?;
    if current_members.matches_active_members(reviewed_members) {
        return Ok(());
    }

    Err(Error::InvalidOperation {
        message: mismatch_message.to_string(),
    })
}

pub(crate) fn ensure_text_file_matches_snapshot_with_limit(
    path: &Path,
    reviewed_content: Option<&str>,
    subject_label: &str,
    max_bytes: usize,
) -> Result<()> {
    let subject_display = format!("{} '{}'", subject_label, path.display());
    fs::ensure_text_file_matches_snapshot_with_limit(
        path,
        reviewed_content,
        &subject_display,
        max_bytes,
    )
}

pub(crate) fn ensure_public_key_snapshot_matches(
    expected: &[PublicKey],
    actual: &[PublicKey],
    mismatch_message: &str,
) -> Result<()> {
    if normalize_public_key_snapshot(expected) == normalize_public_key_snapshot(actual) {
        return Ok(());
    }

    Err(Error::InvalidOperation {
        message: mismatch_message.to_string(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PublicKeySnapshotEntry {
    member_id: MemberId,
    kid: Kid,
}

fn normalize_public_key_snapshot(members: &[PublicKey]) -> Vec<PublicKeySnapshotEntry> {
    let mut normalized = members
        .iter()
        .map(|member| PublicKeySnapshotEntry {
            member_id: MemberId::try_from(member.protected.member_id.clone())
                .expect("public key member_id must be valid"),
            kid: Kid::try_from(member.protected.kid.clone()).expect("public key kid must be valid"),
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}
