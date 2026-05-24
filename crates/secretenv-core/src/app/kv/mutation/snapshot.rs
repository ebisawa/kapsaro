// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Review-time snapshots for KV mutations.
//! Tracks the active member set and target file state used by later execution.

use crate::app::context::review::{ensure_workspace_members_match_snapshot, ReviewedTextFile};
use crate::app::trust::WorkspaceMemberSnapshot;
use crate::feature::kv::mutate::KvRecipientSnapshot;
use crate::format::content::{EncContent, KvEncContent};
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::Result;

use super::super::session::{load_existing_content, KvFileTarget};

pub(super) struct MutationReviewSnapshot {
    target: KvFileTarget,
    file: ReviewedKvFileState,
    file_snapshot: ReviewedTextFile,
    members: WorkspaceMemberSnapshot,
    recipients: KvRecipientSnapshot,
}

enum ReviewedKvFileState {
    Missing,
    Existing(KvEncContent),
}

impl ReviewedKvFileState {
    fn load(target: &KvFileTarget, allow_missing: bool) -> Result<Self> {
        match load_existing_content(target, allow_missing)? {
            Some(content) => Ok(Self::Existing(content)),
            None => Ok(Self::Missing),
        }
    }

    fn as_content(&self) -> Option<&KvEncContent> {
        match self {
            Self::Missing => None,
            Self::Existing(content) => Some(content),
        }
    }
}

impl MutationReviewSnapshot {
    pub(super) fn build(
        target: KvFileTarget,
        workspace_members: WorkspaceMemberSnapshot,
        allow_missing: bool,
    ) -> Result<Self> {
        let recipients = build_recipient_snapshot(&workspace_members);
        let file = ReviewedKvFileState::load(&target, allow_missing)?;
        let file_snapshot = ReviewedTextFile::from_optional_content(
            &target.file_path,
            file.as_content()
                .map(|content| content.as_str().to_string()),
            "KV file",
            resolve_encrypted_artifact_read_limit(&target.file_path),
        );
        Ok(Self {
            target,
            file,
            file_snapshot,
            members: workspace_members,
            recipients,
        })
    }

    pub(super) fn ensure_current(&self, verbose: bool) -> Result<()> {
        self.ensure_members_match(verbose)?;
        self.ensure_file_matches()
    }

    pub(super) fn existing_content(&self) -> Option<&KvEncContent> {
        self.file.as_content()
    }

    pub(super) fn recipients(&self) -> &KvRecipientSnapshot {
        &self.recipients
    }

    pub(super) fn target(&self) -> &KvFileTarget {
        &self.target
    }

    pub(super) fn save_replacement(&self, encrypted: &str) -> Result<()> {
        self.file_snapshot.save_replacement(encrypted)
    }

    pub(super) fn encrypted_content(&self, encrypted: String) -> EncContent {
        EncContent::KvEnc(KvEncContent::new_unchecked(encrypted))
    }

    fn ensure_members_match(&self, verbose: bool) -> Result<()> {
        ensure_workspace_members_match_snapshot(
            &self.target.workspace_root.root_path,
            &self.members,
            verbose,
            "KV active members changed since review and must be reviewed again.",
        )
    }

    fn ensure_file_matches(&self) -> Result<()> {
        self.file_snapshot.ensure_current()
    }
}

fn build_recipient_snapshot(workspace_members: &WorkspaceMemberSnapshot) -> KvRecipientSnapshot {
    KvRecipientSnapshot {
        member_handles: workspace_members.member_handles().to_vec(),
        verified_members: workspace_members.verified_recipients().to_vec(),
    }
}
