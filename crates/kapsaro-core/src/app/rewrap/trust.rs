// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust evaluation for a rewrap batch.
//! Resolves recipient trust across the membership the rewrap will produce.

use std::collections::BTreeMap;

use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{recipient_outcome_from_decision, TrustContext};
use crate::feature::context::expiry::collect_recipient_key_expiry_warnings;
use crate::feature::trust::known_keys::{judge_known_key, KnownKeyJudgment};
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::model::public_key::PublicKey;
use crate::service::trust::CurrentMemberSnapshot;
use crate::{Error, Result};

use super::types::{IncomingPromotionCandidate, RewrapBatchPlan, RewrapTrustPlan};

pub fn build_rewrap_trust(
    plan: &RewrapBatchPlan,
    accepted_promotions: &[IncomingPromotionCandidate],
) -> Result<RewrapTrustPlan> {
    let trust_ctx = &plan.pre_promotion_trust;
    let (post_promotion_members, new_promotion_approvals) =
        load_post_promotion_members(trust_ctx, accepted_promotions)?;
    let verified_recipients = verify_recipient_public_keys(&post_promotion_members)?;
    let recipient_expiry_warnings = collect_recipient_key_expiry_warnings(&verified_recipients)?;
    let post_promotion_members = verified_recipients
        .iter()
        .map(|recipient| recipient.document().clone())
        .collect::<Vec<_>>();
    let post_members = CurrentMemberSnapshot::from_verified_members_by_kid(
        build_post_promotion_index(&post_promotion_members)?,
    )?;
    let evaluator = plan.pre_promotion_evaluator.with_members(post_members);
    let service_approvals = new_promotion_approvals
        .iter()
        .map(|approval| approval.service_approval().clone())
        .collect::<Vec<_>>();
    let decision = evaluator.preflight_output_recipient_keys(
        &post_promotion_members,
        &trust_ctx.self_trust,
        &service_approvals,
    )?;
    let recipient_trust = recipient_outcome_from_decision(decision, trust_ctx.is_interactive)?;
    Ok(RewrapTrustPlan {
        warnings: recipient_expiry_warnings,
        recipient_trust,
        new_promotion_approvals,
        post_promotion_members,
    })
}

pub fn build_post_promotion_trust_context(
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
    let mut new_promotion_approvals = Vec::new();
    for candidate in accepted_promotions {
        replace_post_promotion_member(&mut members, &candidate.public_key);
        let reviewed = crate::app::trust::TrustApprovalCandidate::try_from(candidate)?;
        let known_key_state = judge_known_key(
            &trust_ctx.known_keys,
            reviewed.kid().as_str(),
            reviewed.member_handle().as_str(),
        )?;
        if Some(candidate.review.member_handle.as_str()) == self_member_handle {
            continue;
        }
        if known_key_state == KnownKeyJudgment::New {
            new_promotion_approvals.push(ApprovedKnownKey::from_candidate(&reviewed)?);
        }
    }
    members.sort_by(|left, right| {
        left.protected
            .subject_handle
            .cmp(&right.protected.subject_handle)
    });

    Ok((members, new_promotion_approvals))
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
            return Err(Error::build_config_error(format!(
                "Ambiguous key: kid '{}' found in multiple post-promotion members",
                kid
            )));
        }
    }
    Ok(index)
}
