// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI prompts for trust decisions.

use crate::cli::common::output::text::layout;
use crate::cli::common::output::trust::review::{
    format_candidate_review_lines, print_trust_review_line,
};
use crate::cli::common::prompt::prompt_yes_no;
use console::Style;
use secretenv_core::cli_api::app::trust::enforcement::{
    ArtifactRecipientHandleHint, ArtifactRecipientSetReview, ArtifactRecipientSetSnapshot,
};
use secretenv_core::cli_api::app::trust::{ArtifactRecipientTrustOutcome, TrustApprovalCandidate};
use secretenv_core::cli_api::presentation::kid::format_kid_display_lossy;
use secretenv_core::Result;
use std::collections::{BTreeMap, BTreeSet};

mod recovery;

#[cfg(test)]
pub(crate) use recovery::recover_invalid_trust_store_with_reader;
pub(crate) use recovery::run_with_trust_store_reset_recovery;

pub(crate) fn confirm_signer_key_approval(
    candidate: &TrustApprovalCandidate,
    _context_label: &str,
) -> Result<bool> {
    for line in format_signer_key_review_lines(candidate) {
        print_trust_review_line(&line);
    }
    prompt_yes_no("Approve this key?", false)
}

pub(crate) fn confirm_non_member_acceptance(
    candidate: &TrustApprovalCandidate,
    _context_label: &str,
    recipients: &[String],
) -> Result<bool> {
    for line in format_non_member_signer_review_lines(candidate, recipients) {
        print_trust_review_line(&line);
    }
    prompt_yes_no("Accept this signed artifact once?", false)
}

pub(crate) fn confirm_recipient_approvals(
    candidates: &[TrustApprovalCandidate],
    context_label: &str,
) -> Result<Vec<TrustApprovalCandidate>> {
    let mut approved = Vec::new();
    for candidate in candidates {
        if confirm_recipient_key_approval(candidate, context_label)? {
            approved.push(candidate.clone());
        }
    }
    Ok(approved)
}

pub(crate) fn confirm_recipient_set_approval(
    outcome: &ArtifactRecipientTrustOutcome,
    _context_label: &str,
) -> Result<bool> {
    let ArtifactRecipientTrustOutcome::NeedsManualApproval(review) = outcome else {
        return Ok(true);
    };

    for line in format_recipient_set_review_lines(review) {
        print_trust_review_line(&line);
    }
    prompt_yes_no(&recipient_set_review_prompt(review), false)
}

pub(crate) fn confirm_recipient_key_approval(
    candidate: &TrustApprovalCandidate,
    _context_label: &str,
) -> Result<bool> {
    for line in format_recipient_key_review_lines(candidate) {
        print_trust_review_line(&line);
    }
    prompt_yes_no("Approve this key?", false)
}

pub(crate) fn confirm_member_key_approval(
    candidate: &TrustApprovalCandidate,
    _context_label: &str,
) -> Result<bool> {
    for line in format_member_key_review_lines(candidate) {
        print_trust_review_line(&line);
    }
    prompt_yes_no("Approve this key?", false)
}

fn format_signer_key_review_lines(candidate: &TrustApprovalCandidate) -> Vec<String> {
    let mut lines = format_key_approval_review_lines("This secret was signed by the member below.");
    lines.extend(format_candidate_review_lines(candidate));
    lines
}

fn format_non_member_signer_review_lines(
    candidate: &TrustApprovalCandidate,
    recipients: &[String],
) -> Vec<String> {
    let mut lines = vec![
        "Signer outside active members:".to_string(),
        String::new(),
        "This secret was signed by a key that is not in the current active member list."
            .to_string(),
        "Accept only if you intentionally want to read this artifact once.".to_string(),
        "This decision will not save the signer key as trusted.".to_string(),
        String::new(),
        "Signer".to_string(),
    ];
    lines.extend(format_candidate_review_lines(candidate));
    if let Some(warning) = format_non_member_online_verification_warning(candidate) {
        lines.push(warning);
    }
    if !recipients.is_empty() {
        lines.push(String::new());
        lines.push("Current recipients".to_string());
        lines.extend(
            recipients
                .iter()
                .map(|recipient| format!("  - {}", recipient)),
        );
    }
    lines
}

fn format_non_member_online_verification_warning(
    candidate: &TrustApprovalCandidate,
) -> Option<String> {
    if !candidate.github_binding_configured
        || !candidate.online_verification_attempted
        || candidate.verified_github.is_some()
    {
        return None;
    }

    let message = candidate
        .online_verification_message
        .as_deref()
        .unwrap_or("online verification did not succeed");
    Some(format!(
        "Warning: GitHub online verification did not verify this signer: {}",
        message
    ))
}

fn format_recipient_key_review_lines(candidate: &TrustApprovalCandidate) -> Vec<String> {
    let mut lines =
        format_key_approval_review_lines("This artifact references the member key below.");
    lines.extend(format_candidate_review_lines(candidate));
    lines
}

fn format_member_key_review_lines(candidate: &TrustApprovalCandidate) -> Vec<String> {
    let mut lines = format_key_approval_review_lines("You are approving the member key below.");
    lines.extend(format_candidate_review_lines(candidate));
    lines
}

fn format_key_approval_review_lines(intro: &str) -> Vec<String> {
    vec![
        "Key review required:".to_string(),
        String::new(),
        intro.to_string(),
        "Approve only if this public key belongs to that member.".to_string(),
        "If approved, this key will be remembered on this device for future checks.".to_string(),
        String::new(),
        "Before approving, confirm the fingerprint with the member through a trusted".to_string(),
        "channel, such as an in-person check, a signed message, or a fingerprint shared"
            .to_string(),
        "outside this repository.".to_string(),
        String::new(),
        "Key owner".to_string(),
    ]
}

fn format_recipient_set_review_lines(review: &ArtifactRecipientSetReview) -> Vec<String> {
    let mut lines = recipient_set_review_intro(review.has_approved_set());
    if review.has_approved_set() {
        lines.push("Member changes".to_string());
        lines.extend(format_recipient_diff_rows(&build_recipient_diff_rows(
            review,
        )));
    } else {
        lines.push("Current members".to_string());
        lines.extend(format_recipient_lines(&build_recipient_rows(
            &review.current_snapshot(),
        )));
    }
    lines
}

fn recipient_set_review_prompt(review: &ArtifactRecipientSetReview) -> String {
    if review.has_approved_set() {
        "Update the trusted member set for this secret?".to_string()
    } else {
        "Trust this member set for this secret?".to_string()
    }
}

fn recipient_set_review_intro(changed: bool) -> Vec<String> {
    let mut lines = vec!["Secret sharing review required:".to_string(), String::new()];
    if changed {
        lines.extend([
            style_changed_message("This secret's member set differs from your last review."),
            style_changed_message("Approve only if this member change is expected."),
            style_changed_message("Approval updates the remembered member set on this device."),
        ]);
    } else {
        lines.extend([
            "This secret is shared with the members below.".to_string(),
            "Approve only if this member set is expected for this secret.".to_string(),
            "Approval is remembered on this device for future checks.".to_string(),
        ]);
    }
    lines.push(String::new());
    lines
}

fn style_changed_message(message: &str) -> String {
    Style::new()
        .yellow()
        .bold()
        .for_stderr()
        .apply_to(message)
        .to_string()
}

fn format_recipient_lines(rows: &[ArtifactRecipientReviewRow]) -> Vec<String> {
    let rows = rows
        .iter()
        .map(|row| RecipientDisplayRow::new(&row.kid, row.member_handle.clone()))
        .collect::<Vec<_>>();
    format_member_key_rows(&rows)
}

#[derive(Clone, Copy)]
enum ArtifactRecipientReviewDiffStatus {
    Added,
    Removed,
    Unchanged,
}

#[derive(Clone)]
struct ArtifactRecipientReviewRow {
    member_handle: String,
    kid: String,
}

struct ArtifactRecipientReviewDiffRow {
    status: ArtifactRecipientReviewDiffStatus,
    row: ArtifactRecipientReviewRow,
}

#[derive(Clone)]
struct RecipientDisplayRow {
    member_handle: String,
    key_id: String,
}

fn build_recipient_diff_rows(
    review: &ArtifactRecipientSetReview,
) -> Vec<ArtifactRecipientReviewDiffRow> {
    let current = build_recipient_rows_by_kid(&review.current_snapshot());
    let approved = review
        .approved_snapshot()
        .map(|snapshot| build_recipient_rows_by_kid(&snapshot))
        .unwrap_or_default();
    let all_kids = current
        .keys()
        .chain(approved.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    all_kids
        .into_iter()
        .filter_map(|kid| match (current.get(&kid), approved.get(&kid)) {
            (Some(row), None) => Some(ArtifactRecipientReviewDiffRow {
                status: ArtifactRecipientReviewDiffStatus::Added,
                row: row.clone(),
            }),
            (None, Some(row)) => Some(ArtifactRecipientReviewDiffRow {
                status: ArtifactRecipientReviewDiffStatus::Removed,
                row: row.clone(),
            }),
            (Some(row), Some(_)) => Some(ArtifactRecipientReviewDiffRow {
                status: ArtifactRecipientReviewDiffStatus::Unchanged,
                row: row.clone(),
            }),
            (None, None) => None,
        })
        .collect()
}

fn build_recipient_rows_by_kid(
    snapshot: &ArtifactRecipientSetSnapshot,
) -> BTreeMap<String, ArtifactRecipientReviewRow> {
    build_recipient_rows(snapshot)
        .into_iter()
        .map(|row| (row.kid.clone(), row))
        .collect()
}

fn build_recipient_rows(
    snapshot: &ArtifactRecipientSetSnapshot,
) -> Vec<ArtifactRecipientReviewRow> {
    snapshot
        .recipient_kids
        .iter()
        .map(|kid| ArtifactRecipientReviewRow {
            member_handle: find_recipient_handle(kid, &snapshot.recipient_handle_hints),
            kid: kid.clone(),
        })
        .collect()
}

fn find_recipient_handle(kid: &str, hints: &[ArtifactRecipientHandleHint]) -> String {
    hints
        .iter()
        .find(|hint| hint.kid == kid)
        .map(|hint| hint.recipient_handle.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

impl RecipientDisplayRow {
    fn new(kid: &str, member_handle: String) -> Self {
        Self {
            member_handle,
            key_id: format_kid_display_lossy(kid),
        }
    }
}

fn format_member_key_rows(rows: &[RecipientDisplayRow]) -> Vec<String> {
    let member_width = recipient_member_width(rows);
    let mut lines = vec![format!(
        "  {:member_width$}  key id",
        "member handle",
        member_width = member_width
    )];
    lines.extend(rows.iter().flat_map(|row| {
        layout::format_pair_row("  ", &row.member_handle, &row.key_id, member_width)
    }));
    lines
}

fn recipient_member_width(rows: &[RecipientDisplayRow]) -> usize {
    rows.iter()
        .map(|row| row.member_handle.len())
        .max()
        .unwrap_or("member handle".len())
        .max("member handle".len())
}

fn recipient_diff_marker(status: ArtifactRecipientReviewDiffStatus) -> &'static str {
    match status {
        ArtifactRecipientReviewDiffStatus::Added => "+",
        ArtifactRecipientReviewDiffStatus::Removed => "-",
        ArtifactRecipientReviewDiffStatus::Unchanged => " ",
    }
}

fn style_recipient_diff_line(status: ArtifactRecipientReviewDiffStatus, line: String) -> String {
    match status {
        ArtifactRecipientReviewDiffStatus::Added => {
            Style::new().green().for_stderr().apply_to(line).to_string()
        }
        ArtifactRecipientReviewDiffStatus::Removed => {
            Style::new().red().for_stderr().apply_to(line).to_string()
        }
        ArtifactRecipientReviewDiffStatus::Unchanged => line,
    }
}

fn format_recipient_diff_rows(rows: &[ArtifactRecipientReviewDiffRow]) -> Vec<String> {
    let rows = rows
        .iter()
        .map(|diff| {
            (
                diff.status,
                RecipientDisplayRow::new(&diff.row.kid, diff.row.member_handle.clone()),
            )
        })
        .collect::<Vec<_>>();
    let member_width = recipient_diff_member_width(&rows);
    let mut lines = vec![format!(
        "  change  {:member_width$}  key id",
        "member handle",
        member_width = member_width
    )];
    lines.extend(
        rows.iter()
            .flat_map(|(status, row)| format_recipient_diff_row(*status, row, member_width)),
    );
    lines
}

fn format_recipient_diff_row(
    status: ArtifactRecipientReviewDiffStatus,
    row: &RecipientDisplayRow,
    member_width: usize,
) -> Vec<String> {
    let marker = recipient_diff_marker(status);
    let prefix = format!("  {marker} ");
    layout::format_pair_row(&prefix, &row.member_handle, &row.key_id, member_width)
        .into_iter()
        .map(|line| style_recipient_diff_line(status, line))
        .collect()
}

fn recipient_diff_member_width(
    rows: &[(ArtifactRecipientReviewDiffStatus, RecipientDisplayRow)],
) -> usize {
    rows.iter()
        .map(|(_, row)| row.member_handle.len())
        .max()
        .unwrap_or("member handle".len())
        .max("member handle".len())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_trust_recovery_test.rs"]
mod recovery_tests;

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_trust_recipient_set_test.rs"]
mod recipient_set_tests;
