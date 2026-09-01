// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared trust review orchestration for app-layer commands.

mod artifact_recipient;
mod error;
mod execution;
mod online_verification;
mod persistence;
mod recipient;
mod rewrap;
mod signer;
mod types;

pub use artifact_recipient::{
    review_artifact_output_recipient_set, ArtifactOutputRecipientSetReviewInput,
};
pub(crate) use execution::review_and_save_artifact_recipient_set;
pub use execution::{
    execute_read_with_signer_trust, review_artifact_recipient_set_output,
    review_write_recipient_trust, ArtifactRecipientSetReviewInput, TrustExecutionContext,
    TrustReviewContext,
};
pub use persistence::save_approved_known_key_documents;
pub use recipient::review_recipient_trust_with_confirmation;
// Production injects the online verifier through `execution`; the verifier
// forms are re-exported so the review tests can supply a stub instead.
#[cfg(test)]
pub use recipient::review_recipient_trust_with_confirmation_verifier;
pub use rewrap::review_rewrap_input_trust_requirements_with_confirmation;
#[cfg(test)]
pub use rewrap::review_rewrap_input_trust_requirements_with_confirmation_verifier;
// Both entry points are reached through `execution` in production; the direct
// re-export is what lets the review tests call them without that orchestration.
#[cfg(test)]
pub use signer::{
    enforce_read_trust_member_eligibility, review_signer_trust_with_confirmation_verifier,
};
pub use types::{ReadSignerTrustReviewPlan, SignerTrustLabels, WriteRecipientTrustReviewPlan};

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_review_test.rs"]
mod tests;
