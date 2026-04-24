// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared trust review orchestration for app-layer commands.

mod error;
mod execution;
mod online_verification;
mod persistence;
mod recipient;
mod rewrap;
mod signer;
mod types;

pub(crate) use execution::TrustExecutionContext;
pub(crate) use execution::{execute_read_with_signer_trust, execute_write_with_recipient_trust};
pub(crate) use recipient::review_recipient_trust_with_confirmation;
#[cfg(test)]
pub(crate) use recipient::review_recipient_trust_with_confirmation_verifier;
pub(crate) use rewrap::review_rewrap_signer_requirements_with_confirmation;
#[cfg(test)]
pub(crate) use rewrap::review_rewrap_signer_requirements_with_confirmation_verifier;
#[cfg(test)]
pub(crate) use signer::{
    enforce_read_trust_member_eligibility, review_signer_trust_with_confirmation,
    review_signer_trust_with_confirmation_verifier,
};
pub(crate) use types::{
    ReadSignerTrustReviewPlan, SignerTrustLabels, WriteRecipientTrustReviewPlan,
};

#[cfg(test)]
#[path = "../../../tests/unit/app_trust_review_test.rs"]
mod tests;
