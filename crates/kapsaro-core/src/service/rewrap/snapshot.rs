// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Snapshot checks around incoming promotion and post-promotion recipients.

use crate::io::workspace::members::{
    promote_snapshotted_incoming_members_at, IncomingMemberPromotionSnapshot,
};
use crate::service::key::RecipientKeys;
use crate::service::trust::CurrentMemberSnapshot;
use crate::support::fs::relative::DirectoryFd;
use crate::Result;

use super::types::IncomingPromotionCandidate;

/// Current members and derived recipients fixed after promotion completes.
#[derive(Clone)]
pub(super) struct PostPromotionSnapshot {
    members: CurrentMemberSnapshot,
    recipients: RecipientKeys,
}

impl PostPromotionSnapshot {
    pub(super) fn load_at<D>(workspace: &D) -> Result<Self>
    where
        D: DirectoryFd,
    {
        let members = CurrentMemberSnapshot::load_at(workspace)?;
        let recipients = members.recipient_keys()?;
        Ok(Self {
            members,
            recipients,
        })
    }

    pub(super) fn members(&self) -> &CurrentMemberSnapshot {
        &self.members
    }

    pub(super) fn recipients(&self) -> &RecipientKeys {
        &self.recipients
    }
}

/// Promote the reviewed members through the workspace descriptor of the review.
pub fn promote_accepted_incoming_members<D>(
    workspace: &D,
    accepted_promotions: &[IncomingPromotionCandidate],
) -> Result<Vec<String>>
where
    D: DirectoryFd,
{
    if accepted_promotions.is_empty() {
        return Ok(Vec::new());
    }
    let snapshots = accepted_promotions
        .iter()
        .map(|candidate| IncomingMemberPromotionSnapshot {
            member_handle: candidate.review.member_handle.clone(),
            kid: candidate.review.kid.clone(),
            source_content: candidate.source_content.clone(),
            destination: candidate.destination.clone(),
        })
        .collect::<Vec<_>>();
    promote_snapshotted_incoming_members_at(workspace, &snapshots)
}
