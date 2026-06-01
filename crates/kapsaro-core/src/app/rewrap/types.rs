// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{RecipientTrustOutcome, SignerTrustOutcome, TrustContext};
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::public_key::PublicKey;
use crate::model::public_key_verified::VerifiedRecipientKey;
use std::path::PathBuf;

/// Command inputs for a batch rewrap command before CLI confirmation.
#[derive(Debug, Clone)]
pub struct RewrapBatchPlan {
    pub workspace_root: PathBuf,
    pub pre_promotion_trust: TrustContext,
    pub incoming_report: Option<IncomingVerificationReport>,
    pub artifact_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewrapInputTrustRequirement {
    pub file_path: PathBuf,
    pub signer_outcome: SignerTrustOutcome,
    pub recipient_outcome: RecipientTrustOutcome,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RewrapTrustPlan {
    pub warnings: Vec<String>,
    pub recipient_trust: RecipientTrustOutcome,
    pub accepted_promotion_candidates: Vec<ApprovedKnownKey>,
    pub post_promotion_members: Vec<PublicKey>,
}

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
    pub github_binding_configured: bool,
    pub attestor_pub: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IncomingPromotionCandidate {
    pub review: IncomingVerificationItem,
    pub source_path: PathBuf,
    pub source_content: String,
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

/// Application-layer request for executing a rewrap batch.
#[derive(Clone)]
pub struct RewrapBatchRequest {
    pub options: CommonCommandOptions,
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub accepted_promotions: Vec<IncomingPromotionCandidate>,
}

#[derive(Debug, Clone)]
pub struct VerifiedPostPromotionRecipients {
    verified_members: Vec<VerifiedRecipientKey>,
}

impl VerifiedPostPromotionRecipients {
    pub fn new(verified_members: Vec<VerifiedRecipientKey>) -> Self {
        Self { verified_members }
    }

    pub fn verified_members(&self) -> &[VerifiedRecipientKey] {
        &self.verified_members
    }
}

/// A successfully rewritten file.
pub struct RewrapFileSuccess {
    pub output_path: PathBuf,
}

/// A file that failed to rewrap.
pub struct RewrapFileFailure {
    pub output_path: PathBuf,
    pub error_message: String,
}

/// Outcome of a batch rewrap execution.
pub struct RewrapBatchOutcome {
    pub processed_files: Vec<RewrapFileSuccess>,
    pub failed_files: Vec<RewrapFileFailure>,
    pub promoted_member_handles: Vec<String>,
    pub warnings: Vec<String>,
}
