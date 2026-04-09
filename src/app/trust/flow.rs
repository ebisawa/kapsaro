// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared trust review flow orchestration for app-layer commands.

mod execute;
mod online;
mod persist;
mod review;

pub(crate) use execute::TrustExecutionContext;
pub(crate) use execute::{execute_read_with_signer_trust, execute_write_with_recipient_trust};
#[allow(unused_imports)]
pub(crate) use review::{
    reject_non_member_read_trust, review_recipient_trust_with_handler,
    review_recipient_trust_with_handler_and_verifier,
    review_rewrap_signer_requirements_with_handlers,
    review_rewrap_signer_requirements_with_handlers_and_verifier,
    review_signer_trust_with_handlers, review_signer_trust_with_handlers_and_verifier,
    ReadSignerTrustReviewPlan, SignerTrustLabels, WriteRecipientTrustReviewPlan,
};

#[cfg(test)]
#[path = "../../../tests/unit/app_trust_flow_test.rs"]
mod tests;
