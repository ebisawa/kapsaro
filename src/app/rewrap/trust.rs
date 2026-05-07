// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{enforce_recipients_trust_with_additional, TrustContext};
use crate::feature::context::expiry::collect_recipient_key_expiry_warnings;
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::model::public_key::PublicKey;
use crate::{Error, Result};

use super::types::{IncomingPromotionCandidate, RewrapBatchPlan, RewrapTrustPlan};

pub(crate) fn build_rewrap_trust(
    plan: &RewrapBatchPlan,
    accepted_promotions: &[IncomingPromotionCandidate],
    debug: bool,
) -> Result<RewrapTrustPlan> {
    let trust_ctx = &plan.pre_promotion_trust;
    let (post_promotion_members, accepted_promotion_candidates) =
        load_post_promotion_members(trust_ctx, accepted_promotions)?;
    let verified_recipients = verify_recipient_public_keys(&post_promotion_members, debug)?;
    let recipient_expiry_warnings = collect_recipient_key_expiry_warnings(&verified_recipients)?;
    let post_promotion_members = verified_recipients
        .iter()
        .map(|recipient| recipient.document().clone())
        .collect::<Vec<_>>();
    let mut review_ctx = trust_ctx.clone();
    review_ctx.active_members_by_kid = build_post_promotion_index(&post_promotion_members)?;
    let accepted_known_keys = accepted_promotion_candidates
        .iter()
        .map(KnownKeyIdentity::from)
        .collect::<Vec<_>>();

    let recipient_trust = enforce_recipients_trust_with_additional(
        &review_ctx,
        &post_promotion_members,
        &accepted_known_keys,
    )?;
    let mut warnings = trust_ctx.permission_warnings.clone();
    warnings.extend(recipient_expiry_warnings);

    Ok(RewrapTrustPlan {
        warnings,
        recipient_trust,
        accepted_promotion_candidates,
        post_promotion_members,
    })
}

pub(crate) fn build_post_promotion_trust_context(
    pre_promotion_trust: &TrustContext,
    post_promotion_members: &[PublicKey],
) -> Result<TrustContext> {
    let mut trust_ctx = pre_promotion_trust.clone();
    trust_ctx.active_members_by_kid = build_post_promotion_index(post_promotion_members)?;
    Ok(trust_ctx)
}

fn load_post_promotion_members(
    trust_ctx: &TrustContext,
    accepted_promotions: &[IncomingPromotionCandidate],
) -> Result<(Vec<PublicKey>, Vec<ApprovedKnownKey>)> {
    let mut members = trust_ctx
        .active_members_by_kid
        .values()
        .cloned()
        .collect::<Vec<_>>();
    members.sort_by(|left, right| {
        left.protected
            .subject_handle
            .cmp(&right.protected.subject_handle)
    });
    if accepted_promotions.is_empty() {
        return Ok((members, Vec::new()));
    }

    let self_member_handle = trust_ctx.self_trust.member_handle();
    let mut accepted_promotion_candidates = Vec::new();
    for candidate in accepted_promotions {
        replace_post_promotion_member(&mut members, &candidate.public_key);
        if Some(candidate.review.member_handle.as_str()) == self_member_handle {
            continue;
        }
        accepted_promotion_candidates.push(ApprovedKnownKey::from_review(
            &candidate.review.member_handle,
            &candidate.review.kid,
            candidate.review.attestor_pub.clone(),
            candidate.review.verified_github.as_ref(),
        ));
    }
    members.sort_by(|left, right| {
        left.protected
            .subject_handle
            .cmp(&right.protected.subject_handle)
    });

    Ok((members, accepted_promotion_candidates))
}

fn replace_post_promotion_member(members: &mut Vec<PublicKey>, candidate: &PublicKey) {
    if let Some(existing) = members
        .iter_mut()
        .find(|member| member.protected.subject_handle == candidate.protected.subject_handle)
    {
        *existing = candidate.clone();
        return;
    }

    members.push(candidate.clone());
}

fn build_post_promotion_index(members: &[PublicKey]) -> Result<BTreeMap<String, PublicKey>> {
    let mut index = BTreeMap::new();
    for member in members {
        let kid = member.protected.kid.clone();
        if index.insert(kid.clone(), member.clone()).is_some() {
            return Err(Error::Config {
                message: format!(
                    "Ambiguous key: kid '{}' found in multiple post-promotion members",
                    kid
                ),
            });
        }
    }
    Ok(index)
}
