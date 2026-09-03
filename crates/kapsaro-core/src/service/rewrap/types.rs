// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Data types passed between rewrap planning, trust review, and execution.
//! Carries no behavior of its own; each type models one stage of the batch flow.

use crate::io::verify_online::VerifiedGithubIdentity;
use crate::io::workspace::members::PromotionDestinationState;
use crate::model::public_key::PublicKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingVerificationCategory {
    BindingConfigured,
    Verified,
    Failed,
    NotConfigured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingVerificationItem {
    pub member_handle: String,
    pub kid: String,
    pub category: IncomingVerificationCategory,
    pub message: String,
    pub fingerprint: Option<String>,
    pub verified_github: Option<VerifiedGithubIdentity>,
    pub verified_service_evidence: Option<crate::service::online::VerifiedGitHubEvidence>,
    pub github_binding_configured: bool,
    pub attestor_pub: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IncomingPromotionCandidate {
    pub review: IncomingVerificationItem,
    pub source_content: String,
    /// What `members/active/<handle>.json` held when this candidate was read.
    ///
    /// Promotion replaces that document, so the state it was reviewed against
    /// travels with the candidate and is confirmed again before the write.
    pub destination: PromotionDestinationState,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IncomingPromotionReviewPlan {
    pub failed_candidates: Vec<IncomingPromotionCandidate>,
    pub auto_accepted_candidates: Vec<IncomingPromotionCandidate>,
    pub prompt_candidates: Vec<IncomingPromotionCandidate>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IncomingVerificationReport {
    pub binding_configured: Vec<IncomingPromotionCandidate>,
    pub failed: Vec<IncomingPromotionCandidate>,
    pub not_configured: Vec<IncomingPromotionCandidate>,
}
