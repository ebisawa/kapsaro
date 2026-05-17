// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store management use cases.

pub mod approval;
pub mod candidate;
pub mod enforcement;
pub mod evaluation;
pub mod list;
pub mod management;
pub mod policy;
pub mod recovery;
pub mod review;
pub mod snapshot;
pub mod store;
pub mod types;

pub use candidate::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};
pub use enforcement::{
    enforce_recipients_trust_with_additional, ArtifactRecipientTrustOutcome, RecipientTrustOutcome,
    SignerTrustOutcome,
};
pub use evaluation::{
    derive_self_sig_x, evaluate_output_recipient_set_trust, evaluate_read_artifact_trust,
    evaluate_signer_trust_with_proof,
};
pub use policy::{
    CommandCapability, DecryptPolicy, EncryptPolicy, GetPolicy, ImportPolicy, ReadTrustPolicy,
    RunPolicy, SetPolicy, UnsetPolicy, WriteTrustPolicy,
};
pub use snapshot::{
    load_read_trust_context, TrustContext, WorkspaceMemberSnapshot, WriteRecipientTrustPlan,
};

#[cfg(test)]
pub use enforcement::{build_signer_identity, enforce_recipients_trust, enforce_signer_trust};
#[cfg(test)]
pub use evaluation::enforce_policy_strict_key_checking;
#[cfg(test)]
pub use policy::RewrapInputPolicy;
#[cfg(test)]
pub use snapshot::CommandTrustSnapshot;

#[cfg(test)]
#[path = "../../tests/unit/internal/app_context_trust_test.rs"]
mod snapshot_tests;
