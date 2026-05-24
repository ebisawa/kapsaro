// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust review outcome types shared across app-layer orchestration.
//! Keeps decision data separate from enforcement and review execution logic.

use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::model::trust_store::{RecipientHandleHint, RecipientSetRecord};

use super::candidate::TrustApprovalCandidate;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerTrustOutcome {
    Accepted,
    NeedsKnownKeyApproval(TrustApprovalCandidate),
    NeedsNonMemberAcceptance {
        candidate: TrustApprovalCandidate,
        current_recipients: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientTrustOutcome {
    Accepted,
    NeedsManualApproval(Vec<TrustApprovalCandidate>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactRecipientTrustOutcome {
    Accepted,
    SkippedStrictKeyCheckingNo,
    NeedsManualApproval(Box<ArtifactRecipientSetReview>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecipientSetReview {
    current: ArtifactRecipientSet,
    approved: Option<RecipientSetRecord>,
}

impl ArtifactRecipientSetReview {
    pub fn new(current: ArtifactRecipientSet, approved: Option<RecipientSetRecord>) -> Self {
        Self { current, approved }
    }

    pub fn has_approved_set(&self) -> bool {
        self.approved.is_some()
    }

    pub fn current_snapshot(&self) -> ArtifactRecipientSetSnapshot {
        ArtifactRecipientSetSnapshot::from_current(&self.current)
    }

    pub fn approved_snapshot(&self) -> Option<ArtifactRecipientSetSnapshot> {
        self.approved
            .as_ref()
            .map(ArtifactRecipientSetSnapshot::from_record)
    }

    pub(crate) fn current_set(&self) -> &ArtifactRecipientSet {
        &self.current
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecipientSetSnapshot {
    pub recipient_kids: Vec<String>,
    pub recipient_handle_hints: Vec<ArtifactRecipientHandleHint>,
}

impl ArtifactRecipientSetSnapshot {
    fn from_current(current: &ArtifactRecipientSet) -> Self {
        Self::new(
            current.recipient_kids().to_vec(),
            current.recipient_handle_hints(),
        )
    }

    fn from_record(record: &RecipientSetRecord) -> Self {
        Self::new(
            record.recipient_kids.clone(),
            record.recipient_handle_hints.as_deref().unwrap_or(&[]),
        )
    }

    fn new(recipient_kids: Vec<String>, hints: &[RecipientHandleHint]) -> Self {
        Self {
            recipient_kids,
            recipient_handle_hints: hints
                .iter()
                .map(ArtifactRecipientHandleHint::from_model)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecipientHandleHint {
    pub kid: String,
    pub recipient_handle: String,
}

impl ArtifactRecipientHandleHint {
    fn from_model(hint: &RecipientHandleHint) -> Self {
        Self {
            kid: hint.kid.clone(),
            recipient_handle: hint.recipient_handle.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRecipientKeyTrust {
    pub outcome: RecipientTrustOutcome,
    pub warnings: Vec<String>,
}
