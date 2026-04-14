// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{
    enforce_recipients_trust_with_additional, evaluate_signer_trust_with_proof, CommandCapability,
    SignerTrustOutcome, TrustContext,
};
use crate::feature::context::expiry::collect_recipient_key_expiry_warnings;
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::feature::verify::file::verify_file_content;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::EncryptedContent;
use crate::model::public_key::PublicKey;
use crate::{Error, Result};

use super::types::{
    IncomingPromotionCandidate, RewrapArtifactSnapshot, RewrapBatchPlan, RewrapSignerRequirement,
    RewrapTrustPlan,
};

pub(crate) fn build_rewrap_trust(
    plan: &RewrapBatchPlan,
    accepted_promotions: &[IncomingPromotionCandidate],
) -> Result<RewrapTrustPlan> {
    let trust_ctx = &plan.pre_promotion_trust;
    let (post_promotion_members, accepted_promotion_candidates) =
        load_post_promotion_members(trust_ctx, accepted_promotions)?;
    let recipient_expiry_warnings = collect_recipient_key_expiry_warnings(&post_promotion_members)?;
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
    let current_recipients = collect_recipient_member_ids(&post_promotion_members);
    let signer_requirements = collect_signer_requirements(plan, trust_ctx, &current_recipients)?;

    let mut warnings = trust_ctx.permission_warnings.clone();
    warnings.extend(recipient_expiry_warnings);

    Ok(RewrapTrustPlan {
        warnings,
        recipient_trust,
        signer_requirements,
        accepted_promotion_candidates,
        post_promotion_members,
    })
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
    members.sort_by(|left, right| left.protected.member_id.cmp(&right.protected.member_id));
    if accepted_promotions.is_empty() {
        return Ok((members, Vec::new()));
    }

    let self_member_id = trust_ctx.self_trust.member_id();
    let mut accepted_promotion_candidates = Vec::new();
    for candidate in accepted_promotions {
        replace_post_promotion_member(&mut members, &candidate.public_key);
        if Some(candidate.review.member_id.as_str()) == self_member_id {
            continue;
        }
        accepted_promotion_candidates.push(ApprovedKnownKey::from_review(
            &candidate.review.member_id,
            &candidate.review.kid,
            candidate.review.attestor_pub.clone(),
            candidate.review.verified_github.as_ref(),
        ));
    }
    members.sort_by(|left, right| left.protected.member_id.cmp(&right.protected.member_id));

    Ok((members, accepted_promotion_candidates))
}

fn replace_post_promotion_member(members: &mut Vec<PublicKey>, candidate: &PublicKey) {
    if let Some(existing) = members
        .iter_mut()
        .find(|member| member.protected.member_id == candidate.protected.member_id)
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

fn collect_recipient_member_ids(members: &[PublicKey]) -> Vec<String> {
    let mut recipients: Vec<String> = members
        .iter()
        .map(|member| member.protected.member_id.clone())
        .collect();
    recipients.sort();
    recipients
}

fn collect_signer_requirements(
    plan: &RewrapBatchPlan,
    trust_ctx: &TrustContext,
    current_recipients: &[String],
) -> Result<Vec<RewrapSignerRequirement>> {
    let mut requirements = Vec::new();

    for snapshot in &plan.artifact_snapshots {
        if let Some(requirement) =
            evaluate_file_signer_requirement(snapshot, trust_ctx, current_recipients)?
        {
            requirements.push(requirement);
        }
    }

    Ok(requirements)
}

fn evaluate_file_signer_requirement(
    snapshot: &RewrapArtifactSnapshot,
    trust_ctx: &TrustContext,
    current_recipients: &[String],
) -> Result<Option<RewrapSignerRequirement>> {
    let content = EncryptedContent::detect(snapshot.content.clone())?;
    let proof = match content {
        EncryptedContent::FileEnc(file_content) => {
            verify_file_content(&file_content, false)?.proof.clone()
        }
        EncryptedContent::KvEnc(kv_content) => {
            { verify_kv_content(&kv_content, false)?.proof }.clone()
        }
    };

    let outcome = evaluate_signer_trust_with_proof(
        trust_ctx,
        &proof,
        CommandCapability::Rewrap,
        current_recipients,
    )?;

    if matches!(outcome, SignerTrustOutcome::Accepted) {
        return Ok(None);
    }

    Ok(Some(RewrapSignerRequirement {
        file_path: snapshot.file_path.clone(),
        outcome,
    }))
}
