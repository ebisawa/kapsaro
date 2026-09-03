// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public non-interactive local-trust API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::read::{
    AuthorizedRead, FileReadTarget, NonMemberReadReview, ReadAcceptance, ReadReview,
    ReadSessionDecision, WorkspaceReadDirectories, WorkspaceReadSession,
};
pub use crate::service::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, KnownKeyApprovalEvidence, KnownKeyReview,
    KnownKeyReviewCandidate, LocalTrustStore, ReadTrustExceptions, RecipientSetSubject,
    TrustApproval, TrustApprovalOutcome, TrustCommandSession, TrustDecision, TrustPolicyEvaluator,
    TrustRecipientHandleHint, TrustReviewKind, TrustReviewRequest, VerifiedLocalTrustStore,
    VerifiedLocalTrustStoreLoadResult,
};

pub use crate::service::trust::{
    ArtifactRecipientTrustOutcome, RecipientTrustOutcome, SignerTrustOutcome,
    TrustApprovalCandidate, WriteTrustOptions,
};

pub mod enforcement {
    pub use crate::service::trust::{
        ArtifactRecipientHandleHint, ArtifactRecipientSetReview, ArtifactRecipientSetSnapshot,
    };
}

pub mod list {
    pub use crate::service::trust::list::{
        list_known_keys_command, list_recipient_sets_command, resolve_trust_list_command,
        RecipientSetListItem, RecipientSetListResult, TrustListCommand, TrustListItem,
        TrustListResult,
    };
}

pub mod management {
    pub use crate::service::trust::management::{
        execute_purge, execute_recipient_set_purge, list_purge_candidates,
        list_recipient_set_purge_candidates, remove_known_key_command,
        remove_recipient_set_command, PurgeOutcome, ReviewedPurgeCandidates,
    };
}

pub mod recovery {
    pub use crate::service::trust::recovery::{
        build_trust_store_reset_plan_from_list_command, build_trust_store_reset_plan_from_session,
        classify_trust_store_reset, execute_trust_store_reset,
        observe_trust_store_recovery_from_list_command, observe_trust_store_recovery_from_session,
        TrustStoreRecoveryToken, TrustStoreResetCause, TrustStoreResetLoss, TrustStoreResetPlan,
    };
}

pub mod resign {
    pub use crate::service::trust::resign::{resign_trust_store_command, TrustStoreResignResult};
}

pub mod review {
    pub use crate::service::trust::review::{
        execute_read_with_signer_trust, review_write_recipient_trust, ReadSignerTrustReviewPlan,
        SignerTrustLabels, TrustReviewContext, WriteRecipientTrustReviewPlan,
    };
}
