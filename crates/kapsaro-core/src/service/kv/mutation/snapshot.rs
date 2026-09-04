// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Review-time snapshots for KV mutations.
//! Tracks the active member set and target file state used by later execution.

use crate::feature::kv::mutate::KvRecipientSnapshot;
use crate::format::content::{EncContent, KvEncContent};
use crate::service::artifact::ReviewedTextFile;
use crate::service::trust::{ensure_workspace_members_match_snapshot, ReviewedTrustStore};
use crate::service::trust::{TrustContext, WorkspaceMemberSnapshot};
use crate::service::workspace::WorkspaceWriteCapabilities;
use crate::support::fs::relative::DirectoryFd;
use crate::{Error, Result};

use super::super::session::{capture_reviewed_target, reviewed_kv_content, KvFileTarget};

pub(super) struct MutationReviewSnapshot {
    target: KvFileTarget,
    file: ReviewedKvFileState,
    file_snapshot: ReviewedTextFile,
    members: WorkspaceMemberSnapshot,
    recipients: KvRecipientSnapshot,
    trust_store: ReviewedTrustStore,
}

/// What a KV mutation says when the store it reviewed no longer matches.
pub(super) const KV_TRUST_STORE_CHANGED_MESSAGE: &str =
    "KV trust store changed since review and must be reviewed again.";

enum ReviewedKvFileState {
    Missing,
    Existing(KvEncContent),
}

impl ReviewedKvFileState {
    fn from_capture(target: &KvFileTarget, reviewed: &ReviewedTextFile) -> Self {
        match reviewed_kv_content(target, reviewed) {
            Some(content) => Self::Existing(content),
            None => Self::Missing,
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
        capabilities: &WorkspaceWriteCapabilities<'_>,
        trust_context: &TrustContext,
        allow_missing: bool,
    ) -> Result<Self> {
        let recipients = build_recipient_snapshot(&workspace_members);
        let file_snapshot = capture_reviewed_target(capabilities, &target, allow_missing)?;
        let file = ReviewedKvFileState::from_capture(&target, &file_snapshot);
        let trust_store = load_reviewed_trust_store(capabilities, trust_context)?;
        Ok(Self {
            target,
            file,
            file_snapshot,
            members: workspace_members,
            recipients,
            trust_store,
        })
    }

    pub(super) fn ensure_current(
        &self,
        capabilities: &WorkspaceWriteCapabilities<'_>,
    ) -> Result<()> {
        self.ensure_members_match(capabilities)?;
        self.ensure_file_matches()?;
        self.ensure_trust_store_current(capabilities)
    }

    /// Confirm the secrets document below `dir` is still the reviewed entry.
    ///
    /// The identity is checked as well as the bytes: this guards a document of
    /// secrets that is about to be rewritten, and a name repointed at another
    /// file with the same contents would otherwise pass.
    pub(super) fn ensure_target_current_at<D>(
        &self,
        capabilities: &WorkspaceWriteCapabilities<'_>,
        dir: &D,
    ) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.ensure_members_match(capabilities)?;
        self.file_snapshot
            .ensure_identity_and_content_current_at(dir)
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
        if !self
            .file_snapshot
            .matches_reviewed_state(&current.file_snapshot)?
        {
            return Err(Error::build_invalid_operation_error(
                "KV file changed since review and must be reviewed again.".to_string(),
            ));
        }
        Ok(())
    }

    /// Replace the reviewed document, refusing one that moved before the rename.
    ///
    /// The replacement bytes are staged first and the name is repointed at them
    /// last, and everything the write rests on is confirmed in between: the
    /// member set, and the document itself by identity and content. It has to
    /// happen here and not only earlier: the work that produced these bytes
    /// re-read the artifact, derived the authorization from the trust store and
    /// ran the mutation, and a writer ignoring the directory lock can replace
    /// the target at any point of that. Checking only before the work would let
    /// the bytes land on a document nobody reviewed.
    pub(super) fn save_replacement_at<D>(
        &self,
        capabilities: &WorkspaceWriteCapabilities<'_>,
        dir: &D,
        encrypted: &str,
    ) -> Result<()>
    where
        D: DirectoryFd,
    {
        self.file_snapshot
            .save_replacement_if_current_with_precondition_at(dir, encrypted, || {
                self.ensure_target_current_at(capabilities, dir)
            })
    }

    pub(super) fn encrypted_content(&self, encrypted: String) -> EncContent {
        EncContent::KvEnc(KvEncContent::new_unchecked(encrypted))
    }

    pub(super) fn ensure_trust_store_current(
        &self,
        capabilities: &WorkspaceWriteCapabilities<'_>,
    ) -> Result<()> {
        self.trust_store.ensure_current(capabilities.trust())
    }

    /// Confirm the workspace still holds the member set the review was built on.
    ///
    /// The members are read through the workspace descriptor this command fixed,
    /// the same one the write lands under, so a workspace repointed while the
    /// operator was deciding cannot answer the authorization question from a
    /// tree the review never saw.
    fn ensure_members_match(&self, capabilities: &WorkspaceWriteCapabilities<'_>) -> Result<()> {
        ensure_workspace_members_match_snapshot(
            capabilities.workspace(),
            &self.members,
            "KV active members changed since review and must be reviewed again.",
        )
    }

    fn ensure_file_matches(&self) -> Result<()> {
        self.file_snapshot.ensure_current()
    }
}

/// A KV mutation verifies the trust store it reviews, so a run without a local
/// keystore is reported here rather than passing as an empty store.
fn load_reviewed_trust_store(
    capabilities: &WorkspaceWriteCapabilities<'_>,
    trust_context: &TrustContext,
) -> Result<ReviewedTrustStore> {
    ReviewedTrustStore::load(
        capabilities.trust(),
        trust_context,
        KV_TRUST_STORE_CHANGED_MESSAGE,
    )
}

fn build_recipient_snapshot(workspace_members: &WorkspaceMemberSnapshot) -> KvRecipientSnapshot {
    KvRecipientSnapshot {
        member_handles: workspace_members.member_handles().to_vec(),
        verified_members: workspace_members.verified_recipients().to_vec(),
    }
}
