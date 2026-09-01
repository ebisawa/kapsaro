// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public non-interactive local-trust API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, KnownKeyApprovalEvidence, KnownKeyReview,
    KnownKeyReviewCandidate, LocalTrustStore, ReadTrustExceptions, RecipientSetSubject,
    TrustApproval, TrustApprovalOutcome, TrustDecision, TrustPolicyEvaluator,
    TrustRecipientHandleHint, TrustReviewKind, TrustReviewRequest, VerifiedLocalTrustStore,
    VerifiedLocalTrustStoreLoadResult,
};
