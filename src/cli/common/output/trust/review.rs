// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared trust review formatters.

use console::Style;

use crate::app::rewrap::promotion::PromotionReviewFailure;
use crate::app::trust::TrustApprovalCandidate;
use crate::cli::common::output::text::print_warning_line;
use crate::support::kid::format_kid_display;

pub(crate) fn format_candidate_review_lines(candidate: &TrustApprovalCandidate) -> Vec<String> {
    let kid_display =
        format_kid_display(&candidate.kid).unwrap_or_else(|_| candidate.kid.to_string());
    let mut lines = vec![format!("  kid: {}", kid_display)];
    if let Some(fingerprint) = &candidate.fingerprint {
        lines.push(format!("  attestation fingerprint: {}", fingerprint));
    }
    if let Some(id) = candidate.github_id {
        let mut line = format!("  GitHub account id: {}", id);
        if let Some(login) = &candidate.github_login {
            line.push_str(&format!(" ({})", login));
        }
        if candidate.verified_github.is_some() {
            let verified_mark = Style::new().green().apply_to("\u{2713} verified");
            line.push_str(&format!(" {}", verified_mark));
        }
        lines.push(line);
    } else if candidate.github_binding_configured {
        let warning = if candidate.online_verification_attempted {
            format!(
                "  Warning: GitHub binding claim is present, but online verification did not succeed: {}",
                candidate
                    .online_verification_message
                    .as_deref()
                    .unwrap_or("online verification failed")
            )
        } else {
            "  Warning: GitHub binding claim is present, but this command did not verify it online."
                .to_string()
        };
        lines.push(warning);
    } else {
        lines.push(
            "  Warning: No GitHub binding configured; online verification could not be performed."
                .to_string(),
        );
    }
    if candidate.requires_out_of_band_verification {
        lines.push(
            "  Warning: This key is not yet trusted. Verify the above details with the key owner through a separate channel before approving."
                .to_string(),
        );
    }
    lines
}

pub(crate) fn print_candidate_review(candidate: &TrustApprovalCandidate) {
    for line in format_candidate_review_lines(candidate) {
        if is_warning_line(&line) {
            print_warning_line(&line);
        } else {
            eprintln!("{}", line);
        }
    }
}

pub(crate) fn print_failed_promotion_reviews(failed_candidates: &[PromotionReviewFailure]) {
    for candidate in failed_candidates {
        eprintln!(
            "Skipping incoming member '{}' due to failed verification: {}",
            candidate.member_id, candidate.message
        );
    }
}

fn is_warning_line(line: &str) -> bool {
    line.trim_start().starts_with("Warning:")
}

#[cfg(test)]
#[path = "../../../../../tests/unit/cli_common_trust_test.rs"]
mod tests;
