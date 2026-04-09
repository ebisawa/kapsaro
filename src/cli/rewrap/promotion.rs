// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! TOFU confirmation and promotion output for rewrap.

use crate::app::rewrap::promotion::{PromotionReviewPrompt, PromotionReviewView};
use crate::cli::common::output::trust::review::{
    print_candidate_review, print_failed_promotion_reviews,
};
use crate::cli::common::prompt::prompt_yes_no_with_reader;
use crate::Result;
use std::io::BufRead;

pub(crate) fn confirm_incoming_promotions(
    review_view: &PromotionReviewView,
    input: &mut impl BufRead,
) -> Result<Vec<String>> {
    print_failed_promotion_reviews(&review_view.failed_candidates);
    let mut accepted = Vec::new();
    for prompt in &review_view.prompt_candidates {
        if prompt_tofu_confirmation(prompt, input)? {
            accepted.push(prompt.candidate.member_id.to_string());
        }
    }
    Ok(accepted)
}

pub(crate) fn print_promotion_summary(promoted_ids: &[String], quiet: bool) {
    if quiet {
        return;
    }
    for member_id in promoted_ids {
        eprintln!("Promoted '{}' from incoming to active", member_id);
    }
}

fn prompt_tofu_confirmation(
    prompt: &PromotionReviewPrompt,
    input: &mut impl BufRead,
) -> Result<bool> {
    eprintln!("Incoming member '{}':", prompt.candidate.member_id);
    print_candidate_review(&prompt.candidate);
    prompt_yes_no_with_reader("  Accept?", false, input)
}

#[cfg(test)]
#[path = "../../../tests/unit/cli_rewrap_internal_test.rs"]
mod tests;
