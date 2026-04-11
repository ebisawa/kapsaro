// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! View builders for member command output.

use crate::app::member::approval::MemberApprovalResult;
use crate::app::member::types::{MemberListResult, MemberShowResult, MemberVerificationResult};
use crate::app::trust::TrustApprovalCandidate;

pub(crate) struct MemberListEntryView<'a> {
    pub(crate) member_id: &'a str,
    pub(crate) document: &'a serde_json::Value,
}

pub(crate) struct MemberListView<'a> {
    pub(crate) active: Vec<MemberListEntryView<'a>>,
    pub(crate) incoming: Vec<MemberListEntryView<'a>>,
    pub(crate) warnings: &'a [String],
}

pub(crate) struct MemberGithubClaimView<'a> {
    pub(crate) id: u64,
    pub(crate) login: &'a str,
}

pub(crate) struct MemberShowView<'a> {
    pub(crate) member_id: &'a str,
    pub(crate) kid: &'a str,
    pub(crate) expires_at: &'a str,
    pub(crate) created_at: Option<&'a str>,
    pub(crate) algorithm: String,
    pub(crate) ssh_fingerprint: &'a str,
    pub(crate) github_claim: Option<MemberGithubClaimView<'a>>,
    pub(crate) verification_status: &'a str,
    pub(crate) membership_status: &'a str,
    pub(crate) verification_warnings: &'a [String],
    pub(crate) document: &'a serde_json::Value,
}

pub(crate) struct MemberVerificationItemView<'a> {
    pub(crate) member_id: &'a str,
    pub(crate) verified: bool,
    pub(crate) message: &'a str,
    pub(crate) fingerprint: Option<&'a str>,
    pub(crate) matched_key_id: Option<i64>,
}

pub(crate) struct MemberVerificationResultsView<'a> {
    pub(crate) results: Vec<MemberVerificationItemView<'a>>,
}

pub(crate) struct MemberApprovalItemView<'a> {
    pub(crate) member_id: &'a str,
    pub(crate) kid: &'a str,
    pub(crate) verified: bool,
    pub(crate) approved: bool,
    pub(crate) review_required: bool,
    pub(crate) already_known: bool,
    pub(crate) message: &'a str,
    pub(crate) fingerprint: Option<&'a str>,
    pub(crate) github_id: Option<u64>,
    pub(crate) github_login: Option<&'a str>,
    pub(crate) github_binding_configured: bool,
    pub(crate) review_candidate: TrustApprovalCandidate,
}

pub(crate) struct MemberApprovalResultsView<'a> {
    pub(crate) results: Vec<MemberApprovalItemView<'a>>,
}

pub(crate) fn build_member_list_view(result: &MemberListResult) -> MemberListView<'_> {
    MemberListView {
        active: result
            .active
            .iter()
            .map(|member| MemberListEntryView {
                member_id: &member.member_id,
                document: &member.document,
            })
            .collect(),
        incoming: result
            .incoming
            .iter()
            .map(|member| MemberListEntryView {
                member_id: &member.member_id,
                document: &member.document,
            })
            .collect(),
        warnings: &result.warnings,
    }
}

pub(crate) fn build_member_show_view(result: &MemberShowResult) -> MemberShowView<'_> {
    let algorithm = format!("{} + {}", result.member.kem_curve, result.member.sig_curve);
    MemberShowView {
        member_id: &result.member.member_id,
        kid: &result.member.kid,
        expires_at: &result.member.expires_at,
        created_at: result.member.created_at.as_deref(),
        algorithm,
        ssh_fingerprint: &result.member.ssh_attestation_fingerprint,
        github_claim: result
            .member
            .github_claim
            .as_ref()
            .map(|claim| MemberGithubClaimView {
                id: claim.id,
                login: &claim.login,
            }),
        verification_status: result.member.verification_status.as_str(),
        membership_status: result.status.as_str(),
        verification_warnings: &result.member.verification_warnings,
        document: &result.member.document,
    }
}

pub(crate) fn build_member_verification_results_view(
    results: &[MemberVerificationResult],
) -> MemberVerificationResultsView<'_> {
    MemberVerificationResultsView {
        results: results
            .iter()
            .map(|result| MemberVerificationItemView {
                member_id: &result.member_id,
                verified: result.verified,
                message: &result.message,
                fingerprint: result.fingerprint.as_deref(),
                matched_key_id: result.matched_key_id,
            })
            .collect(),
    }
}

pub(crate) fn build_member_approval_results_view(
    results: &[MemberApprovalResult],
) -> MemberApprovalResultsView<'_> {
    MemberApprovalResultsView {
        results: results
            .iter()
            .filter(|result| !result.already_known)
            .map(|result| MemberApprovalItemView {
                member_id: &result.member_id,
                kid: &result.kid,
                verified: result.verified,
                approved: result.approved,
                review_required: result.review_required,
                already_known: result.already_known,
                message: &result.message,
                fingerprint: result.fingerprint.as_deref(),
                github_id: result.github_id,
                github_login: result.github_login.as_deref(),
                github_binding_configured: result.github_binding_configured,
                review_candidate: result.into(),
            })
            .collect(),
    }
}
