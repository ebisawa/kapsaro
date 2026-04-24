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
pub(crate) struct RewrapBatchPlan {
    pub(crate) workspace_root: PathBuf,
    pub(crate) pre_promotion_trust: TrustContext,
    pub(crate) incoming_report: Option<IncomingVerificationReport>,
    pub(crate) artifact_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RewrapSignerRequirement {
    pub(crate) file_path: PathBuf,
    pub(crate) outcome: SignerTrustOutcome,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RewrapTrustPlan {
    pub(crate) warnings: Vec<String>,
    pub(crate) recipient_trust: RecipientTrustOutcome,
    pub(crate) accepted_promotion_candidates: Vec<ApprovedKnownKey>,
    pub(crate) post_promotion_members: Vec<PublicKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IncomingVerificationCategory {
    BindingConfigured,
    Verified,
    Failed,
    NotConfigured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IncomingVerificationItem {
    pub member_id: String,
    pub kid: String,
    pub category: IncomingVerificationCategory,
    pub message: String,
    pub fingerprint: Option<String>,
    pub verified_github: Option<VerifiedGithubIdentity>,
    pub github_binding_configured: bool,
    pub attestor_pub: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IncomingPromotionCandidate {
    pub review: IncomingVerificationItem,
    pub source_path: PathBuf,
    pub source_content: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct IncomingPromotionReviewPlan {
    pub failed_candidates: Vec<IncomingPromotionCandidate>,
    pub auto_accepted_candidates: Vec<IncomingPromotionCandidate>,
    pub prompt_candidates: Vec<IncomingPromotionCandidate>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct IncomingVerificationReport {
    pub binding_configured: Vec<IncomingPromotionCandidate>,
    pub failed: Vec<IncomingPromotionCandidate>,
    pub not_configured: Vec<IncomingPromotionCandidate>,
}

/// Application-layer request for executing a rewrap batch.
#[derive(Clone)]
pub(crate) struct RewrapBatchRequest {
    pub options: CommonCommandOptions,
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub accepted_promotions: Vec<IncomingPromotionCandidate>,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedPostPromotionRecipients {
    verified_members: Vec<VerifiedRecipientKey>,
}

impl VerifiedPostPromotionRecipients {
    pub(crate) fn new(verified_members: Vec<VerifiedRecipientKey>) -> Self {
        Self { verified_members }
    }

    pub(crate) fn verified_members(&self) -> &[VerifiedRecipientKey] {
        &self.verified_members
    }
}

/// A successfully rewritten file.
pub(crate) struct RewrapFileSuccess {
    pub(crate) output_path: PathBuf,
}

/// A file that failed to rewrap.
pub(crate) struct RewrapFileFailure {
    pub(crate) output_path: PathBuf,
    pub(crate) error_message: String,
}

/// Outcome of a batch rewrap execution.
pub(crate) struct RewrapBatchOutcome {
    pub(crate) processed_files: Vec<RewrapFileSuccess>,
    pub(crate) failed_files: Vec<RewrapFileFailure>,
    pub(crate) promoted_member_ids: Vec<String>,
    pub(crate) warnings: Vec<String>,
}
