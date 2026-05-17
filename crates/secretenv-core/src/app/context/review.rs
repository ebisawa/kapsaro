// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared review snapshot guards for app-layer commands.

use crate::app::trust::WorkspaceMemberSnapshot;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::support::fs;
use crate::support::fs::atomic;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

pub fn ensure_workspace_members_match_snapshot(
    workspace_root: &Path,
    reviewed_members: &WorkspaceMemberSnapshot,
    verbose: bool,
    mismatch_message: &str,
) -> Result<()> {
    let current_members = WorkspaceMemberSnapshot::load(workspace_root, verbose)?;
    if current_members.matches_active_members(reviewed_members) {
        return Ok(());
    }

    Err(Error::build_invalid_operation_error(
        mismatch_message.to_string(),
    ))
}

pub fn ensure_text_file_matches_snapshot_with_limit(
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedTextFile {
    path: PathBuf,
    reviewed_content: Option<String>,
    subject_label: String,
    max_bytes: usize,
}

impl ReviewedTextFile {
    pub fn load_existing(path: &Path, subject_label: &str, max_bytes: usize) -> Result<Self> {
        let content = fs::load_text_with_limit(path, max_bytes, subject_label)?;
        Ok(Self::from_optional_content(
            path,
            Some(content),
            subject_label,
            max_bytes,
        ))
    }

    pub fn from_optional_content(
        path: &Path,
        reviewed_content: Option<String>,
        subject_label: &str,
        max_bytes: usize,
    ) -> Self {
        Self {
            path: path.to_path_buf(),
            reviewed_content,
            subject_label: subject_label.to_string(),
            max_bytes,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn content(&self) -> Option<&str> {
        self.reviewed_content.as_deref()
    }

    pub fn require_content(&self) -> Result<&str> {
        self.content().ok_or_else(|| {
            Error::build_invalid_operation_error(format!(
                "{} content is required",
                self.subject_label
            ))
        })
    }

    pub fn ensure_current(&self) -> Result<()> {
        ensure_text_file_matches_snapshot_with_limit(
            &self.path,
            self.content(),
            &self.subject_label,
            self.max_bytes,
        )
    }

    pub fn save_replacement(&self, content: &str) -> Result<()> {
        atomic::save_text(&self.path, content)
    }
}

pub fn ensure_public_key_snapshot_matches(
    expected: &[PublicKey],
    actual: &[PublicKey],
    mismatch_message: &str,
) -> Result<()> {
    if normalize_public_key_snapshot(expected) == normalize_public_key_snapshot(actual) {
        return Ok(());
    }

    Err(Error::build_invalid_operation_error(
        mismatch_message.to_string(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PublicKeySnapshotEntry {
    member_handle: MemberHandle,
    kid: Kid,
}

fn normalize_public_key_snapshot(members: &[PublicKey]) -> Vec<PublicKeySnapshotEntry> {
    let mut normalized = members
        .iter()
        .map(|member| PublicKeySnapshotEntry {
            member_handle: MemberHandle::try_from(member.protected.subject_handle.clone())
                .expect("public key member_handle must be valid"),
            kid: Kid::try_from(member.protected.kid.clone()).expect("public key kid must be valid"),
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}
