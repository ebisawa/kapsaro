// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust operations shared by API callers.

pub(crate) mod command;
mod core;

pub use crate::config::types::{
    StrictKeyChecking, StrictKeyCheckingResolution, StrictKeyCheckingSource,
};

pub use command::TrustCommandSession;
pub use core::{
    ApprovalConflictHandling, CurrentMemberSnapshot, KnownKeyApprovalEvidence, KnownKeyReview,
    KnownKeyReviewCandidate, LocalTrustStore, ReadTrustExceptions, RecipientSetSubject,
    TrustApproval, TrustApprovalOutcome, TrustDecision, TrustPolicyEvaluator,
    TrustRecipientHandleHint, TrustReviewKind, TrustReviewRequest, VerifiedLocalTrustStore,
    VerifiedLocalTrustStoreLoadResult,
};
pub(crate) use core::{NonMemberSignerReview, ReadTrustReview};

pub(crate) mod approval;
pub(crate) mod candidate;
pub(crate) mod evaluation;
pub(crate) mod list;
pub(crate) mod management;
pub(crate) mod outcome;
pub(crate) mod persistence;
pub(crate) mod recovery;
pub(crate) mod resign;
pub(crate) mod review;
pub(crate) mod signer_snapshot;
pub(crate) mod snapshot;
pub(crate) mod store;
pub(crate) mod transaction;
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
