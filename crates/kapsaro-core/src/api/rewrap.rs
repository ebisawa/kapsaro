// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public operation-bound rewrap API.
//! Re-exports only the capability and options issued by service trust evaluation.

pub use crate::service::rewrap::{
    AuthorizedRewrapInput, RewrapAcceptance, RewrapDirectories, RewrapNonMemberReview,
    RewrapOptions, RewrapPromotionOutcome, RewrapPromotionReview, RewrapReview, RewrapSession,
    RewrapSessionDecision, RewrapTarget, RewrapTargetListing,
};

pub mod promotion {
    pub use crate::service::rewrap::promotion::{
        PromotionReviewFailure, PromotionReviewPrompt, PromotionReviewView,
    };
}
