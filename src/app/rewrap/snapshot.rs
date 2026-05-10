// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Snapshot checks around incoming promotion and post-promotion recipients.

use std::path::Path;

use crate::app::context::review::ensure_public_key_snapshot_matches;
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::io::workspace::members::{
    load_active_member_files, promote_snapshotted_incoming_members, IncomingMemberPromotionSnapshot,
};
use crate::model::public_key::PublicKey;
use crate::Result;

use super::types::{IncomingPromotionCandidate, VerifiedPostPromotionRecipients};

pub(crate) fn promote_accepted_incoming_members(
    workspace_root: &Path,
    accepted_promotions: &[IncomingPromotionCandidate],
) -> Result<Vec<String>> {
    if accepted_promotions.is_empty() {
        return Ok(Vec::new());
    }
    let snapshots = accepted_promotions
        .iter()
        .map(|candidate| IncomingMemberPromotionSnapshot {
            member_handle: candidate.review.member_handle.clone(),
            kid: candidate.review.kid.clone(),
            source_path: candidate.source_path.clone(),
            source_content: candidate.source_content.clone(),
        })
        .collect::<Vec<_>>();
    promote_snapshotted_incoming_members(workspace_root, &snapshots)
}

pub(crate) fn load_verified_post_promotion_members(
    workspace_root: &Path,
    expected: &[PublicKey],
) -> Result<VerifiedPostPromotionRecipients> {
    let actual = load_active_member_files(workspace_root)?;
    ensure_post_promotion_members_match(expected, &actual)?;
    let verified_members = verify_recipient_public_keys(&actual, false)?;
    Ok(VerifiedPostPromotionRecipients::new(verified_members))
}

fn ensure_post_promotion_members_match(expected: &[PublicKey], actual: &[PublicKey]) -> Result<()> {
    ensure_public_key_snapshot_matches(
        expected,
        actual,
        "Rewrap post-promotion active members changed and must be reviewed again.",
    )
}
