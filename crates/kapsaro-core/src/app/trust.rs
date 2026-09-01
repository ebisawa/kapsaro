// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store management use cases.

pub(crate) mod approval;
pub(crate) mod candidate;
pub(crate) mod cli_read;
pub(crate) mod evaluation;
pub(crate) mod list;
pub(crate) mod management;
pub(crate) mod outcome;
pub(crate) mod policy;
pub(crate) mod recovery;
pub(crate) mod resign;
pub(crate) mod review;
pub(crate) mod snapshot;
pub(crate) mod store;
pub(crate) mod types;

pub use candidate::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};
pub use cli_read::{evaluate_file_after_cli_review, evaluate_kv_after_cli_review};
pub(crate) use evaluation::{
    artifact_recipient_outcome_from_decision, build_read_artifact_trust_plan,
    push_signature_verification_warnings, recipient_outcome_from_decision,
    signer_outcome_from_decision,
};
pub use evaluation::{evaluate_output_recipient_set_trust, ReadArtifactTrustPlan};
pub use outcome::{
    ArtifactRecipientHandleHint, ArtifactRecipientSetReview, ArtifactRecipientSetSnapshot,
    ArtifactRecipientTrustOutcome, RecipientTrustOutcome, SignerTrustOutcome,
};
pub(crate) use policy::RewrapInputPolicy;
pub use policy::{
    CommandCapability, DecryptPolicy, EncryptPolicy, GetPolicy, ImportPolicy, ListPolicy,
    ReadTrustPolicy, RunPolicy, SetPolicy, UnsetPolicy, WriteTrustPolicy,
};
pub(crate) use snapshot::CommandTrustSnapshot;
pub use snapshot::{
    load_read_trust_context, TrustContext, WorkspaceMemberSnapshot, WriteRecipientTrustPlan,
};

// Snapshot policy enforcement is also exercised directly by trust tests.
#[cfg(test)]
pub(crate) use evaluation::enforce_policy_strict_key_checking;

#[cfg(test)]
#[path = "../../tests/unit/internal/app_context_trust_test.rs"]
mod snapshot_tests;
