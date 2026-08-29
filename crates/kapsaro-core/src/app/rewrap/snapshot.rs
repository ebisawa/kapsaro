// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Snapshot checks around incoming promotion and post-promotion recipients.

use crate::app::context::review::ensure_public_key_snapshot_matches;
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::io::workspace::members::{
    load_active_member_files_at, promote_snapshotted_incoming_members_at,
    IncomingMemberPromotionSnapshot,
};
use crate::model::public_key::PublicKey;
use crate::support::fs::relative::DirectoryFd;
use crate::Result;

use super::types::{IncomingPromotionCandidate, VerifiedPostPromotionRecipients};

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

/// Read back the member set the promotion produced, through the same descriptor.
pub fn load_verified_post_promotion_members<D>(
    workspace: &D,
    expected: &[PublicKey],
) -> Result<VerifiedPostPromotionRecipients>
where
    D: DirectoryFd,
{
    let actual = load_active_member_files_at(workspace)?;
    ensure_post_promotion_members_match(expected, &actual)?;
    let verified_members = verify_recipient_public_keys(&actual)?;
    Ok(VerifiedPostPromotionRecipients::new(verified_members))
}

fn ensure_post_promotion_members_match(expected: &[PublicKey], actual: &[PublicKey]) -> Result<()> {
    ensure_public_key_snapshot_matches(
        expected,
        actual,
        "Rewrap post-promotion active members changed and must be reviewed again.",
    )
}
