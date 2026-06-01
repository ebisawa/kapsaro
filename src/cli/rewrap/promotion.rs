// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! TOFU confirmation and promotion output for rewrap.

use crate::cli::common::output::trust::review::{
    print_candidate_review, print_failed_promotion_reviews,
};
use crate::cli::common::prompt::prompt_yes_no;
#[cfg(test)]
use crate::cli::common::prompt::prompt_yes_no_with_reader;
use kapsaro_core::cli_api::app::rewrap::promotion::{PromotionReviewPrompt, PromotionReviewView};
use kapsaro_core::Result;
#[cfg(test)]
use std::io::BufRead;

fn promotion_prompt_label() -> &'static str {
    "Accept?"
}

pub(crate) fn confirm_incoming_promotions(
    review_view: &PromotionReviewView,
) -> Result<Vec<String>> {
    collect_confirmed_promotions(review_view, prompt_tofu_confirmation)
}

#[cfg(test)]
pub(crate) fn confirm_incoming_promotions_with_reader(
    review_view: &PromotionReviewView,
    input: &mut impl BufRead,
) -> Result<Vec<String>> {
    collect_confirmed_promotions(review_view, |prompt| {
        prompt_tofu_confirmation_with_reader(prompt, input)
    })
}

fn collect_confirmed_promotions<F>(
    review_view: &PromotionReviewView,
    mut confirm: F,
) -> Result<Vec<String>>
where
    F: FnMut(&PromotionReviewPrompt) -> Result<bool>,
{
    print_failed_promotion_reviews(&review_view.failed_candidates);
    let mut accepted = Vec::new();
    for prompt in &review_view.prompt_candidates {
        if confirm(prompt)? {
            accepted.push(prompt.candidate.member_handle.to_string());
        }
    }
    Ok(accepted)
}

pub(crate) fn print_promotion_summary(promoted_ids: &[String], quiet: bool) {
    if quiet {
        return;
    }
    for member_handle in promoted_ids {
        eprintln!("Promoted '{}' from incoming to active", member_handle);
    }
}

fn prompt_tofu_confirmation(prompt: &PromotionReviewPrompt) -> Result<bool> {
    eprintln!("Incoming member '{}':", prompt.candidate.member_handle);
    print_candidate_review(&prompt.candidate);
    prompt_yes_no(promotion_prompt_label(), false)
}

#[cfg(test)]
fn prompt_tofu_confirmation_with_reader(
    prompt: &PromotionReviewPrompt,
    input: &mut impl BufRead,
) -> Result<bool> {
    eprintln!("Incoming member '{}':", prompt.candidate.member_handle);
    print_candidate_review(&prompt.candidate);
    prompt_yes_no_with_reader(promotion_prompt_label(), false, input)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_rewrap_internal_test.rs"]
mod tests;
