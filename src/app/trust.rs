// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store management use cases.

pub(crate) mod approval;
pub(crate) mod enforcement;
pub(crate) mod evaluation;
pub(crate) mod flow;
pub(crate) mod list;
pub(crate) mod management;
pub(crate) mod paths;
pub(crate) mod policy;
pub(crate) mod snapshot;
pub(crate) mod store;
pub(crate) mod types;

#[allow(unused_imports)]
pub(crate) use enforcement::{
    build_signer_identity, build_trust_approval_candidate, enforce_recipients_trust,
    enforce_recipients_trust_with_additional, enforce_signer_trust, RecipientTrustOutcome,
    SignerTrustOutcome, TrustApprovalCandidate,
};
#[allow(unused_imports)]
pub(crate) use evaluation::{
    build_read_signer_trust, current_self_sig_x, enforce_policy_strict_key_checking,
    evaluate_signer_trust_with_proof, ReadSignerTrustPlan,
};
#[allow(unused_imports)]
pub(crate) use policy::{
    CommandCapability, DecryptPolicy, EncryptPolicy, GetPolicy, ImportPolicy, ReadTrustPolicy,
    RewrapInputPolicy, RunPolicy, SetPolicy, TrustPolicy, UnsetPolicy, WriteTrustPolicy,
};
#[allow(unused_imports)]
pub(crate) use snapshot::{
    load_read_trust_context, CommandTrustSnapshot, TrustContext, WorkspaceMemberSnapshot,
    WriteRecipientTrustPlan,
};

#[cfg(test)]
#[path = "../../tests/unit/app_context_trust_test.rs"]
mod snapshot_tests;
