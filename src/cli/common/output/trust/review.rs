// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared trust review formatters.

use crate::cli::common::output::text::layout;
use crate::cli::common::output::text::print_warning_line;
use secretenv_core::cli_api::app::rewrap::promotion::PromotionReviewFailure;
use secretenv_core::cli_api::app::trust::TrustApprovalCandidate;
use secretenv_core::cli_api::presentation::kid::format_kid_display;

const REVIEW_LABEL_WIDTH: usize = 19;

pub(crate) fn format_candidate_review_lines(candidate: &TrustApprovalCandidate) -> Vec<String> {
    let kid_display =
        format_kid_display(&candidate.kid).unwrap_or_else(|_| candidate.kid.to_string());
    let mut lines = format_candidate_review_field_lines("member handle", &candidate.member_handle);
    lines.extend(format_candidate_review_field_lines("key id", &kid_display));
    lines.extend(format_candidate_review_field_lines(
        "SSH fingerprint",
        candidate.fingerprint.as_deref().unwrap_or("unknown"),
    ));
    lines.extend(format_candidate_review_field_lines(
        "GitHub account",
        &format_github_account(candidate),
    ));
    lines
}

pub(crate) fn print_candidate_review(candidate: &TrustApprovalCandidate) {
    for line in format_candidate_review_lines(candidate) {
        print_trust_review_line(&line);
    }
}

pub(crate) fn print_trust_review_line(line: &str) {
    if is_warning_line(line) {
        print_warning_line(line);
    } else {
        eprintln!("{}", line);
    }
}

pub(crate) fn print_failed_promotion_reviews(failed_candidates: &[PromotionReviewFailure]) {
    for line in format_failed_promotion_review_lines(failed_candidates) {
        eprintln!("{line}");
    }
}

pub(crate) fn format_failed_promotion_review_lines(
    failed_candidates: &[PromotionReviewFailure],
) -> Vec<String> {
    failed_candidates
        .iter()
        .flat_map(|candidate| {
            layout::format_value_lines(
                "",
                &format!(
                    "Skipping incoming member '{}' due to failed verification: {}",
                    candidate.member_handle, candidate.message
                ),
            )
        })
        .collect()
}

fn format_candidate_review_field_lines(label: &str, value: &str) -> Vec<String> {
    let prefix = format!("  {label:<REVIEW_LABEL_WIDTH$}");
    layout::format_value_lines(&prefix, value)
}

fn is_warning_line(line: &str) -> bool {
    line.trim_start().starts_with("Warning:")
}

fn format_github_account(candidate: &TrustApprovalCandidate) -> String {
    if candidate.verified_github.is_some() {
        return format_verified_github_account(candidate);
    }
    if candidate.github_binding_configured {
        return format!(
            "not verified ({})",
            candidate
                .online_verification_message
                .as_deref()
                .unwrap_or("online verification was not completed")
        );
    }
    "not configured".to_string()
}

fn format_verified_github_account(candidate: &TrustApprovalCandidate) -> String {
    let Some(id) = candidate.github_id else {
        return "verified".to_string();
    };
    match &candidate.github_login {
        Some(login) => format!("{} (id: {}, verified)", login, id),
        None => format!("id: {} (verified)", id),
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_trust_test.rs"]
mod tests;
