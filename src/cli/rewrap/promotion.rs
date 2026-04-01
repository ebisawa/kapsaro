// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! TOFU confirmation and promotion output for rewrap.

use crate::app::rewrap::promotion::{
    build_promotion_decision, PromotionBlockError, PromotionDecision, PromotionWarning,
};
use crate::app::rewrap::types::{IncomingVerificationItem, IncomingVerificationReport};
use crate::{Error, Result};
use std::io::BufRead;

pub(crate) fn confirm_incoming_promotions(
    report: &IncomingVerificationReport,
    is_interactive: bool,
    input: &mut impl BufRead,
) -> Result<Vec<String>> {
    let decision = build_promotion_decision(report, is_interactive);
    resolve_promotion_decision(&decision, input)
}

pub(crate) fn print_promotion_summary(
    report: &IncomingVerificationReport,
    accepted_ids: &[String],
    quiet: bool,
) {
    if quiet {
        return;
    }
    let rejected_count = print_incoming_promotion_items(&report.verified, accepted_ids, true)
        + print_incoming_promotion_items(&report.failed, accepted_ids, false)
        + print_incoming_promotion_items(&report.not_configured, accepted_ids, true);
    if rejected_count > 0 && accepted_ids.is_empty() {
        eprintln!(
            "No incoming members promoted ({} rejected). Continuing with rewrap.",
            rejected_count
        );
    }
}

fn print_incoming_promotion_items(
    items: &[IncomingVerificationItem],
    accepted_ids: &[String],
    show_skipped: bool,
) -> usize {
    let mut rejected = 0;
    for result in items {
        if accepted_ids.contains(&result.member_id) {
            eprintln!("Promoted '{}' from incoming to active", result.member_id);
        } else if show_skipped {
            eprintln!("Skipped '{}' (rejected by user)", result.member_id);
            rejected += 1;
        }
    }
    rejected
}

fn resolve_promotion_decision(
    decision: &PromotionDecision,
    input: &mut impl BufRead,
) -> Result<Vec<String>> {
    match decision {
        PromotionDecision::None => Ok(vec![]),
        PromotionDecision::Prompt { candidates } => {
            let mut accepted = Vec::new();
            for result in candidates {
                if prompt_tofu_confirmation(result, input)? {
                    accepted.push(result.member_id.clone());
                }
            }
            Ok(accepted)
        }
        PromotionDecision::Blocked { warnings, error } => {
            print_promotion_warnings(warnings);
            Err(build_promotion_error(*error))
        }
    }
}

fn print_promotion_warnings(warnings: &[PromotionWarning]) {
    for warning in warnings {
        match warning {
            PromotionWarning::VerificationFailed { member_id, message } => {
                eprintln!("Warning: {}: {}", member_id, message);
            }
        }
    }
}

fn build_promotion_error(error: PromotionBlockError) -> Error {
    match error {
        PromotionBlockError::OnlineVerificationFailed => Error::Verify {
            rule: "V-ONLINE-VERIFY".to_string(),
            message: "Online verification failed for incoming member(s).".to_string(),
        },
        PromotionBlockError::TofuConfirmationRequired => Error::Verify {
            rule: "V-TOFU".to_string(),
            message: "TOFU confirmation required for incoming members but stdin is not a terminal."
                .to_string(),
        },
    }
}

fn prompt_tofu_confirmation(
    result: &IncomingVerificationItem,
    input: &mut impl BufRead,
) -> Result<bool> {
    eprintln!("Incoming member '{}':", result.member_id);
    if let Some(account) = &result.github_account {
        eprintln!("  GitHub: {} (id: {})", account.login, account.id);
    } else {
        eprintln!("  GitHub: no binding configured");
    }
    if let Some(fingerprint) = &result.fingerprint {
        eprintln!("  SSH key fingerprint: {}", fingerprint);
    }
    eprint!("  Accept? [y/N] ");

    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|e| Error::io_with_source(format!("Failed to read user input: {}", e), e))?;
    Ok(line.trim().eq_ignore_ascii_case("y"))
}
