// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap planning.
//! Works out which artifacts and recipients a key rotation has to touch.

use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, WORKSPACE_INCOMING_MEMBER_CONTEXT,
};
use crate::io::workspace::members::{
    capture_promotion_destination_at, open_member_documents_at, MemberStatus,
    PromotionDestinationState,
};
use crate::model::public_key::PublicKey;
use crate::service::trust::TrustApprovalCandidateBuilder;
use crate::support::fs::relative::DirectoryFd;
use crate::Result;
use std::collections::BTreeMap;

use super::types::{
    IncomingPromotionCandidate, IncomingVerificationCategory, IncomingVerificationItem,
    IncomingVerificationReport,
};

fn build_incoming_report(
    incoming_index: &BTreeMap<String, IncomingSnapshot>,
) -> Result<Option<IncomingVerificationReport>> {
    if incoming_index.is_empty() {
        return Ok(None);
    }

    let mut report = IncomingVerificationReport::default();
    for snapshot in incoming_index.values() {
        let candidate = build_incoming_candidate(snapshot)?;
        match candidate.review.category {
            IncomingVerificationCategory::BindingConfigured => {
                report.binding_configured.push(candidate);
            }
            IncomingVerificationCategory::Failed => report.failed.push(candidate),
            IncomingVerificationCategory::NotConfigured => report.not_configured.push(candidate),
            // Offline verification cannot reach Verified: that category is set
            // by the online check, which runs on candidates this report feeds.
            IncomingVerificationCategory::Verified => {}
        }
    }

    Ok(Some(report))
}

pub(crate) fn load_incoming_report_at<D>(
    workspace: &D,
) -> Result<Option<IncomingVerificationReport>>
where
    D: DirectoryFd,
{
    build_incoming_report(&load_incoming_index(workspace)?)
}

fn build_incoming_candidate(snapshot: &IncomingSnapshot) -> Result<IncomingPromotionCandidate> {
    let review = match verify_public_key_for_verification_context(
        &snapshot.public_key,
        WORKSPACE_INCOMING_MEMBER_CONTEXT,
    ) {
        Ok(verified) => build_pending_review(snapshot, &verified.verified_public_key)?,
        Err(error) => IncomingVerificationItem {
            member_handle: snapshot.public_key.protected.subject_handle.clone(),
            kid: snapshot.public_key.protected.kid.clone(),
            category: IncomingVerificationCategory::Failed,
            message: format!(
                "Offline verification failed: {}",
                error.format_user_message()
            ),
            fingerprint: None,
            verified_github: None,
            verified_service_evidence: None,
            github_binding_configured: github_binding_configured(&snapshot.public_key),
            attestor_pub: None,
        },
    };

    Ok(IncomingPromotionCandidate {
        review,
        source_content: snapshot.source_content.clone(),
        destination: snapshot.destination.clone(),
        public_key: snapshot.public_key.clone(),
    })
}

fn build_pending_review(
    snapshot: &IncomingSnapshot,
    verified: &crate::model::public_key::VerifiedSigningPublicKey,
) -> Result<IncomingVerificationItem> {
    let candidate =
        TrustApprovalCandidateBuilder::from_verified_signing_public_key(verified)?.build();
    let (category, message) = build_pending_review_category(candidate.github_binding_configured());

    Ok(IncomingVerificationItem {
        member_handle: snapshot.public_key.protected.subject_handle.clone(),
        kid: snapshot.public_key.protected.kid.clone(),
        category,
        message,
        fingerprint: candidate.fingerprint().map(str::to_string),
        verified_github: None,
        verified_service_evidence: None,
        github_binding_configured: candidate.github_binding_configured(),
        attestor_pub: Some(candidate.attestor_pub().to_string()),
    })
}

fn github_binding_configured(public_key: &PublicKey) -> bool {
    public_key
        .protected
        .binding_claims
        .as_ref()
        .and_then(|claims| claims.github_account.as_ref())
        .is_some()
}

fn build_pending_review_category(
    binding_configured: bool,
) -> (IncomingVerificationCategory, String) {
    if binding_configured {
        (
            IncomingVerificationCategory::BindingConfigured,
            "GitHub binding configured; online verification will run if trust update is required"
                .to_string(),
        )
    } else {
        (
            IncomingVerificationCategory::NotConfigured,
            "No binding_claims.github_account configured".to_string(),
        )
    }
}

#[derive(Debug, Clone)]
struct IncomingSnapshot {
    source_content: String,
    destination: PromotionDestinationState,
    public_key: PublicKey,
}

/// Read every incoming document together with the active document it would
/// replace, so both sides of a promotion are reviewed as one state.
///
/// Both sides are read through the workspace descriptor the command bound to,
/// which is the descriptor the promotion later checks its snapshots against.
///
/// Each incoming document is read once, and the bytes kept for the promotion are
/// the bytes that were verified and shown to the operator. Reading the name a
/// second time to get them would put a window between the review and the capture
/// in which the document could be replaced, and the promotion's own check only
/// compares against what that second read returned.
fn load_incoming_index<D>(workspace: &D) -> Result<BTreeMap<String, IncomingSnapshot>>
where
    D: DirectoryFd,
{
    let documents = open_member_documents_at(workspace, MemberStatus::Incoming)?;
    let mut index = BTreeMap::new();
    for name in documents.names() {
        let document = documents.load_verified_document(name)?;
        let member_handle = document.public_key.protected.subject_handle.clone();
        let destination = capture_promotion_destination_at(workspace, &member_handle)?;
        index.insert(
            member_handle,
            IncomingSnapshot {
                source_content: document.content,
                destination,
                public_key: document.public_key,
            },
        );
    }
    Ok(index)
}
