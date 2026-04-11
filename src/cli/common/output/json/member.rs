// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON renderers for member commands.

use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::member::{
    MemberApprovalResultsView, MemberListView, MemberVerificationResultsView,
};
use crate::Result;
use serde::Serialize;

#[derive(Serialize)]
struct MemberListOutput<'a> {
    active: Vec<&'a serde_json::Value>,
    incoming: Vec<&'a serde_json::Value>,
}

#[derive(Serialize)]
struct MemberVerificationResultsOutput<'a> {
    results: Vec<MemberVerificationJsonItem<'a>>,
}

#[derive(Serialize)]
struct MemberVerificationJsonItem<'a> {
    member_id: &'a str,
    verified: bool,
    message: &'a str,
    fingerprint: Option<&'a str>,
    matched_key_id: Option<i64>,
}

#[derive(Serialize)]
struct MemberApprovalResultsOutput<'a> {
    results: Vec<MemberApprovalJsonItem<'a>>,
}

#[derive(Serialize)]
struct MemberApprovalJsonItem<'a> {
    member_id: &'a str,
    kid: &'a str,
    verified: bool,
    approved: bool,
    review_required: bool,
    already_known: bool,
    message: &'a str,
    fingerprint: Option<&'a str>,
    github_id: Option<u64>,
    github_login: Option<&'a str>,
    github_binding_configured: bool,
}

pub(crate) fn print_member_list(view: &MemberListView<'_>) -> Result<()> {
    print_json_output(&MemberListOutput {
        active: view.active.iter().map(|member| member.document).collect(),
        incoming: view.incoming.iter().map(|member| member.document).collect(),
    })
}

pub(crate) fn print_empty_member_list() -> Result<()> {
    print_json_output(&serde_json::json!({
        "active": [],
        "incoming": [],
    }))
}

pub(crate) fn print_member_verification_results(
    view: &MemberVerificationResultsView<'_>,
) -> Result<()> {
    let output = MemberVerificationResultsOutput {
        results: view
            .results
            .iter()
            .map(|result| MemberVerificationJsonItem {
                member_id: result.member_id,
                verified: result.verified,
                message: result.message,
                fingerprint: result.fingerprint,
                matched_key_id: result.matched_key_id,
            })
            .collect(),
    };
    print_json_output(&output)
}

pub(crate) fn print_member_approval_results(view: &MemberApprovalResultsView<'_>) -> Result<()> {
    let output = MemberApprovalResultsOutput {
        results: view
            .results
            .iter()
            .map(|result| MemberApprovalJsonItem {
                member_id: result.member_id,
                kid: result.kid,
                verified: result.verified,
                approved: result.approved,
                review_required: result.review_required,
                already_known: result.already_known,
                message: result.message,
                fingerprint: result.fingerprint,
                github_id: result.github_id,
                github_login: result.github_login,
                github_binding_configured: result.github_binding_configured,
            })
            .collect(),
    };
    print_json_output(&output)
}
