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

pub use execution::TrustExecutionContext;
pub use execution::{
    execute_read_with_signer_trust, execute_write_with_recipient_trust,
    review_generated_artifact_recipient_set, GeneratedArtifactRecipientSetReview,
};
pub use persistence::save_approved_known_key_warnings;
pub use recipient::review_recipient_trust_with_confirmation;
#[cfg(test)]
pub use recipient::review_recipient_trust_with_confirmation_verifier;
pub use rewrap::review_rewrap_input_trust_requirements_with_confirmation;
#[cfg(test)]
pub use rewrap::review_rewrap_input_trust_requirements_with_confirmation_verifier;
#[cfg(test)]
pub use signer::{
    enforce_read_trust_member_eligibility, review_signer_trust_with_confirmation,
    review_signer_trust_with_confirmation_verifier,
};
pub use types::{ReadSignerTrustReviewPlan, SignerTrustLabels, WriteRecipientTrustReviewPlan};

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_review_test.rs"]
mod tests;
