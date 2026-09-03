// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;

use kapsaro_core::api::rewrap::promotion::{
    PromotionReviewFailure, PromotionReviewPrompt, PromotionReviewView,
};
use kapsaro_core::api::trust::TrustApprovalCandidate;

use super::{confirm_incoming_promotions_with_reader, promotion_prompt_label};

fn build_prompt(member_handle: &str) -> PromotionReviewPrompt {
    let kid = match member_handle {
        "alice" => "KAD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob" => "KBD1AAAA1111BBBB2222CCCC3333DDDD",
        _ => "KCD1AAAA1111BBBB2222CCCC3333DDDD",
    };
    PromotionReviewPrompt {
        candidate: TrustApprovalCandidate::for_test_review(
            member_handle,
            kid,
            Some("SHA256:abc".to_string()),
            true,
            None,
            true,
            Some("verified".to_string()),
            true,
        ),
    }
}

fn build_review_view(
    failed_candidates: Vec<PromotionReviewFailure>,
    prompt_candidates: Vec<PromotionReviewPrompt>,
) -> PromotionReviewView {
    PromotionReviewView {
        failed_candidates,
        prompt_candidates,
    }
}

#[test]
fn test_confirm_incoming_promotions_accepts_mixed_prompt_responses() {
    let review_view = build_review_view(vec![], vec![build_prompt("alice"), build_prompt("bob")]);
    let mut input = Cursor::new(b"y\nn\n" as &[u8]);

    let result = confirm_incoming_promotions_with_reader(&review_view, &mut input).unwrap();

    assert_eq!(result, vec!["alice".to_string()]);
}

#[test]
fn test_confirm_incoming_promotions_ignores_failed_candidates() {
    let review_view = build_review_view(
        vec![PromotionReviewFailure {
            member_handle: "carol".to_string(),
            message: "verification failed".to_string(),
        }],
        vec![build_prompt("alice")],
    );
    let mut input = Cursor::new(b"y\n" as &[u8]);

    let result = confirm_incoming_promotions_with_reader(&review_view, &mut input).unwrap();

    assert_eq!(result, vec!["alice".to_string()]);
}

#[test]
fn test_confirm_incoming_promotions_empty_view_returns_empty() {
    let review_view = build_review_view(vec![], vec![]);
    let mut input = Cursor::new(b"" as &[u8]);

    let result = confirm_incoming_promotions_with_reader(&review_view, &mut input).unwrap();

    assert!(result.is_empty());
}

#[test]
fn test_promotion_prompt_label_has_no_indent() {
    assert_eq!(promotion_prompt_label(), "Accept?");
}
