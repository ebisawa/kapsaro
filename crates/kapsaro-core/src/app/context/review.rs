// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared review snapshot guards for app-layer commands.

use crate::app::context::execution::ExecutionContext;
use crate::app::trust::store::load_execution_trust_store;
use crate::app::trust::{TrustContext, WorkspaceMemberSnapshot};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::model::trust_store::TrustStoreProtected;
use crate::support::fs::relative::{self, open_dir_identity, DirectoryFd, OpenDir};
use crate::support::fs::snapshot::TextFileSnapshot;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::Path;
use std::sync::Arc;

/// Confirm the members held under `workspace` are still the reviewed ones.
///
/// The member set is read through the descriptor the command bound to rather
/// than through the configured path: resolving that path again would let a
/// workspace repointed mid-command answer with another tree's member set, and
/// this is the gate a write is let through on.
pub fn ensure_workspace_members_match_snapshot<D>(
    workspace: &D,
    reviewed_members: &WorkspaceMemberSnapshot,
    mismatch_message: &str,
) -> Result<()>
where
    D: DirectoryFd,
{
    let current_members = WorkspaceMemberSnapshot::load_at(workspace)?;
    if current_members.matches_active_members(reviewed_members) {
        return Ok(());
    }

    Err(Error::build_invalid_operation_error(
        mismatch_message.to_string(),
    ))
}

/// A text file held open exactly as the operator reviewed it, together with the
/// directory it was reached through.
///
/// The descriptors captured at review time are what later checks compare
/// against, so a name repointed at another inode — or a directory path
/// repointed at another tree — between review and execution is reported rather
/// than acted on.
#[derive(Debug)]
pub struct ReviewedTextFile {
    snapshot: TextFileSnapshot,
    subject_label: String,
    max_bytes: usize,
}

impl ReviewedTextFile {
    pub fn load_existing_at(
        dir: Arc<OpenDir>,
        name: &str,
        subject_label: &str,
        max_bytes: usize,
    ) -> Result<Self> {
        let snapshot = TextFileSnapshot::capture_at(dir, name, max_bytes, subject_label)?;
        if snapshot.content().is_none() {
            return Err(Error::build_not_found_error(format!(
                "Failed to read file {}: no such file",
                format_path_relative_to_cwd(snapshot.path())
            )));
        }
        Ok(Self::from_snapshot(snapshot, subject_label, max_bytes))
    }

    /// Record the state of a file the caller has already inspected.
    ///
    /// A target that is not there yet is captured as an absence, which is as
    /// much part of the review as any content: a file appearing afterwards was
    /// never seen.
    pub fn capture_optional_at(
        dir: Arc<OpenDir>,
        name: &str,
        subject_label: &str,
        max_bytes: usize,
    ) -> Result<Self> {
        let snapshot = TextFileSnapshot::capture_at(dir, name, max_bytes, subject_label)?;
        Ok(Self::from_snapshot(snapshot, subject_label, max_bytes))
    }

    fn from_snapshot(snapshot: TextFileSnapshot, subject_label: &str, max_bytes: usize) -> Self {
        Self {
            snapshot,
            subject_label: subject_label.to_string(),
            max_bytes,
        }
    }

    pub fn directory(&self) -> &Arc<OpenDir> {
        self.snapshot.directory()
    }

    pub fn name(&self) -> &str {
        self.snapshot.name()
    }

    pub fn path(&self) -> &Path {
        self.snapshot.path()
    }

    pub fn content(&self) -> Option<&str> {
        self.snapshot.content()
    }

    pub fn require_content(&self) -> Result<&str> {
        self.content().ok_or_else(|| {
            Error::build_invalid_operation_error(format!(
                "{} content is required",
                self.subject_label
            ))
        })
    }

    /// Whether two reviews of the same command saw the same file and content.
    ///
    /// The entry name and the bytes are only half of it: two reviews holding the
    /// same name below two different directories saw two different files, and
    /// only the directory descriptors say which tree each one came from.
    pub fn matches_reviewed_state(&self, other: &Self) -> Result<bool> {
        if self.name() != other.name() || self.content() != other.content() {
            return Ok(false);
        }
        Ok(open_dir_identity(self.directory().as_ref())?
            == open_dir_identity(other.directory().as_ref())?)
    }

    /// Refuse to act through a directory other than the one that was reviewed.
    ///
    /// Every check and write below takes the entry name relative to the
    /// descriptor the caller hands over, so a caller holding another directory
    /// would otherwise answer about, or replace, an entry of the same name in a
    /// tree nobody reviewed.
    fn ensure_bound_directory<D>(&self, dir: &D) -> Result<()>
    where
        D: DirectoryFd,
    {
        if open_dir_identity(self.directory().as_ref())? == open_dir_identity(dir)? {
            return Ok(());
        }
        Err(Error::build_invalid_operation_error(format!(
            "{} was reviewed under another directory and must be reviewed again.",
            self.subject_display()
        )))
    }

    pub fn ensure_current(&self) -> Result<()> {
        self.snapshot
            .ensure_current(&self.subject_display(), self.max_bytes)
    }

    /// Confirm the file below `dir` still holds the text that was reviewed.
    ///
    /// `dir` has to be the reviewed directory, but within it the name is opened
    /// again and only its bytes compared, which says nothing about whether the
    /// entry is still the same inode. That is only half of what a caller acting
    /// on the file needs, so this stays private and every caller goes through
    /// [`Self::ensure_identity_and_content_current_at`].
    fn ensure_current_at<D>(&self, dir: &D) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.ensure_bound_directory(dir)?;
        relative::ensure_text_file_content_matches_at(
            dir,
            self.name(),
            self.content(),
            &self.subject_display(),
            self.max_bytes,
        )
    }

    /// Confirm the file below `dir` is the very entry that was reviewed.
    ///
    /// The contents are compared first, which is what names an entry that is
    /// gone or is no longer a regular file. What is left after that is a name
    /// repointed at another regular file holding the same bytes, and only the
    /// descriptor captured at review time can tell that apart.
    pub fn ensure_identity_and_content_current_at<D>(&self, dir: &D) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.ensure_current_at(dir)?;
        if self.snapshot.still_holds_in(dir)? {
            return Ok(());
        }
        Err(Error::build_invalid_operation_error(format!(
            "{} changed since review and must be reviewed again.",
            self.subject_display()
        )))
    }

    pub fn save_replacement_at<D>(&self, dir: &D, content: &str) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.ensure_bound_directory(dir)?;
        relative::save_text_at(dir, self.name(), content)
    }

    fn subject_display(&self) -> String {
        format!("{} '{}'", self.subject_label, self.path().display())
    }
}

/// Trust store state as it stood at review time, re-read through the trust
/// directory the command opened rather than through the path naming it.
///
/// `changed_message` is the command's own account of what moved, so each caller
/// reports the change in the terms the operator was asked to decide in.
pub struct ReviewedTrustStore<'a> {
    execution: &'a ExecutionContext,
    protected: Option<TrustStoreProtected>,
    changed_message: &'static str,
}

impl<'a> ReviewedTrustStore<'a> {
    /// Record trust store state the caller has already read.
    pub fn from_protected(
        execution: &'a ExecutionContext,
        protected: Option<TrustStoreProtected>,
        changed_message: &'static str,
    ) -> Self {
        Self {
            execution,
            protected,
            changed_message,
        }
    }

    /// Read the trust store the review rests on and confirm it is the state
    /// `trust_context` was derived from.
    ///
    /// The context was built from an earlier read of the same store, so a
    /// mismatch here means the store moved while the command was still
    /// assembling its review.
    pub fn load(
        execution: &'a ExecutionContext,
        trust_context: &TrustContext,
        changed_message: &'static str,
    ) -> Result<Self> {
        let protected = load_reviewed_protected(execution)?;
        ensure_trust_context_matches(&protected, trust_context, changed_message)?;
        Ok(Self::from_protected(execution, protected, changed_message))
    }

    pub fn ensure_current(&self) -> Result<()> {
        let current = load_reviewed_protected(self.execution)?;
        if current == self.protected {
            return Ok(());
        }
        Err(Error::build_invalid_operation_error(
            self.changed_message.to_string(),
        ))
    }
}

/// Read the trust store through the trust directory the command opened, so the
/// review and the write that follows it agree on which directory they mean.
fn load_reviewed_protected(execution: &ExecutionContext) -> Result<Option<TrustStoreProtected>> {
    Ok(load_execution_trust_store(execution)?.map(|state| state.protected))
}

fn ensure_trust_context_matches(
    protected: &Option<TrustStoreProtected>,
    trust_context: &TrustContext,
    changed_message: &'static str,
) -> Result<()> {
    let (known_keys, recipient_sets) = protected
        .as_ref()
        .map(|state| (&state.known_keys[..], &state.recipient_sets[..]))
        .unwrap_or_default();
    if known_keys == trust_context.known_keys && recipient_sets == trust_context.recipient_sets {
        return Ok(());
    }
    Err(Error::build_invalid_operation_error(
        changed_message.to_string(),
    ))
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

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_context_review_test.rs"]
mod tests;

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
