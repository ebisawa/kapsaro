// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Review-time snapshots for KV mutations.
//! Tracks the active member set and target file state used by later execution.

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::review::{ensure_workspace_members_match_snapshot, ReviewedTextFile};
use crate::app::trust::store::load_optional_trust_store_for_member;
use crate::app::trust::{TrustContext, WorkspaceMemberSnapshot};
use crate::feature::kv::mutate::KvRecipientSnapshot;
use crate::format::content::{EncContent, KvEncContent};
use crate::model::trust_store::TrustStoreProtected;
use crate::support::fs::relative::DirectoryFd;
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::{Error, Result};

use super::super::session::{load_existing_content, KvFileTarget};

pub(super) struct MutationReviewSnapshot {
    target: KvFileTarget,
    file: ReviewedKvFileState,
    file_snapshot: ReviewedTextFile,
    members: WorkspaceMemberSnapshot,
    recipients: KvRecipientSnapshot,
    trust_store: MutationTrustStoreSnapshot,
}

pub(super) struct MutationTrustStoreSnapshot {
    options: CommonCommandOptions,
    owner_handle: String,
    protected: Option<TrustStoreProtected>,
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
        options: &CommonCommandOptions,
        owner_handle: &str,
        trust_context: &TrustContext,
        allow_missing: bool,
    ) -> Result<Self> {
        let recipients = build_recipient_snapshot(&workspace_members);
        let file = ReviewedKvFileState::load(&target, allow_missing)?;
        let trust_store = MutationTrustStoreSnapshot::load(options, owner_handle, trust_context)?;
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
            trust_store,
        })
    }

    pub(super) fn ensure_current(&self) -> Result<()> {
        self.ensure_members_match()?;
        self.ensure_file_matches()?;
        self.ensure_trust_store_current()
    }

    pub(super) fn ensure_current_at<D>(&self, dir: &D) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.ensure_members_match()?;
        self.file_snapshot.ensure_current_at(dir)?;
        self.trust_store.ensure_current()
    }

    pub(super) fn ensure_target_current_at<D>(&self, dir: &D) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.ensure_members_match()?;
        self.file_snapshot.ensure_current_at(dir)
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

    pub(super) fn ensure_reviewed_state_matches(&self, current: &Self) -> Result<()> {
        if !self.members.matches_active_members(&current.members) {
            return Err(Error::build_invalid_operation_error(
                "KV active members changed since review and must be reviewed again.".to_string(),
            ));
        }
        if self.file_snapshot != current.file_snapshot {
            return Err(Error::build_invalid_operation_error(
                "KV file changed since review and must be reviewed again.".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn save_replacement_at<D>(&self, dir: &D, encrypted: &str) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.file_snapshot.save_replacement_at(dir, encrypted)
    }

    pub(super) fn encrypted_content(&self, encrypted: String) -> EncContent {
        EncContent::KvEnc(KvEncContent::new_unchecked(encrypted))
    }

    pub(super) fn ensure_trust_store_current(&self) -> Result<()> {
        self.trust_store.ensure_current()
    }

    fn ensure_members_match(&self) -> Result<()> {
        ensure_workspace_members_match_snapshot(
            &self.target.workspace_root.root_path,
            &self.members,
            "KV active members changed since review and must be reviewed again.",
        )
    }

    fn ensure_file_matches(&self) -> Result<()> {
        self.file_snapshot.ensure_current()
    }
}

impl MutationTrustStoreSnapshot {
    pub(super) fn from_protected(
        options: &CommonCommandOptions,
        owner_handle: &str,
        protected: Option<TrustStoreProtected>,
    ) -> Self {
        Self {
            options: options.clone(),
            owner_handle: owner_handle.to_string(),
            protected,
        }
    }

    fn load(
        options: &CommonCommandOptions,
        owner_handle: &str,
        trust_context: &TrustContext,
    ) -> Result<Self> {
        let (_, state) = load_optional_trust_store_for_member(options, owner_handle)?;
        let protected = state.map(|state| state.protected);
        ensure_trust_context_matches(&protected, trust_context)?;
        Ok(Self {
            options: options.clone(),
            owner_handle: owner_handle.to_string(),
            protected,
        })
    }

    pub(super) fn ensure_current(&self) -> Result<()> {
        let (_, state) = load_optional_trust_store_for_member(&self.options, &self.owner_handle)?;
        let current = state.map(|state| state.protected);
        if current == self.protected {
            return Ok(());
        }
        Err(build_trust_store_changed_error())
    }
}

fn ensure_trust_context_matches(
    protected: &Option<TrustStoreProtected>,
    trust_context: &TrustContext,
) -> Result<()> {
    let (known_keys, recipient_sets) = protected
        .as_ref()
        .map(|state| (&state.known_keys[..], &state.recipient_sets[..]))
        .unwrap_or_default();
    if known_keys == trust_context.known_keys && recipient_sets == trust_context.recipient_sets {
        return Ok(());
    }
    Err(build_trust_store_changed_error())
}

fn build_trust_store_changed_error() -> Error {
    Error::build_invalid_operation_error(
        "KV trust store changed since review and must be reviewed again.".to_string(),
    )
}

fn build_recipient_snapshot(workspace_members: &WorkspaceMemberSnapshot) -> KvRecipientSnapshot {
    KvRecipientSnapshot {
        member_handles: workspace_members.member_handles().to_vec(),
        verified_members: workspace_members.verified_recipients().to_vec(),
    }
}
