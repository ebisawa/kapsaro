// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store management use cases.

pub(crate) mod approval;
pub(crate) mod candidate;
pub(crate) mod enforcement;
pub(crate) mod evaluation;
pub(crate) mod list;
pub(crate) mod management;
pub(crate) mod policy;
pub(crate) mod recovery;
pub(crate) mod review;
pub(crate) mod snapshot;
pub(crate) mod store;
pub(crate) mod types;

pub(crate) use candidate::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};
pub(crate) use enforcement::{
    enforce_recipients_trust_with_additional, ArtifactRecipientTrustOutcome, RecipientTrustOutcome,
    SignerTrustOutcome,
};
pub(crate) use evaluation::{
    derive_self_sig_x, evaluate_output_recipient_set_trust, evaluate_read_artifact_trust,
    evaluate_signer_trust_with_proof,
};
pub(crate) use policy::{
    CommandCapability, DecryptPolicy, EncryptPolicy, GetPolicy, ImportPolicy, ReadTrustPolicy,
    RunPolicy, SetPolicy, UnsetPolicy, WriteTrustPolicy,
};
pub(crate) use snapshot::{
    load_read_trust_context, TrustContext, WorkspaceMemberSnapshot, WriteRecipientTrustPlan,
};

#[cfg(test)]
pub(crate) use enforcement::{
    build_signer_identity, enforce_recipients_trust, enforce_signer_trust,
};
#[cfg(test)]
pub(crate) use evaluation::enforce_policy_strict_key_checking;
#[cfg(test)]
pub(crate) use policy::RewrapInputPolicy;
#[cfg(test)]
pub(crate) use snapshot::CommandTrustSnapshot;

#[cfg(test)]
#[path = "../../tests/unit/internal/app_context_trust_test.rs"]
mod snapshot_tests;
