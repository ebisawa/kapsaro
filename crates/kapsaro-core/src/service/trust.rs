// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust operations shared by API callers.

pub(crate) mod command;
mod core;

pub use command::TrustCommandSession;
pub use core::*;

pub(crate) mod approval;
pub(crate) mod candidate;
pub(crate) mod evaluation;
pub(crate) mod list;
pub(crate) mod management;
pub(crate) mod outcome;
pub(crate) mod recovery;
pub(crate) mod resign;
pub(crate) mod review;
pub(crate) mod snapshot;
pub(crate) mod store;
pub(crate) mod types;

pub use candidate::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};
pub use evaluation::evaluate_output_recipient_set_trust;
pub(crate) use evaluation::{
    artifact_recipient_outcome_from_decision, push_signature_verification_warnings,
    recipient_outcome_from_decision, signer_outcome_from_decision,
};
pub use outcome::{
    ArtifactRecipientHandleHint, ArtifactRecipientSetReview, ArtifactRecipientSetSnapshot,
    ArtifactRecipientTrustOutcome, RecipientTrustOutcome, SignerTrustOutcome,
};
pub(crate) use snapshot::{ensure_workspace_members_match_snapshot, ReviewedTrustStore};
pub use snapshot::{
    TrustContext, WorkspaceMemberSnapshot, WriteRecipientTrustPlan, WriteTrustOptions,
};
