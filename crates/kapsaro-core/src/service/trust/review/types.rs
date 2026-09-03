// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Plan structs bundling trust outcomes and labels for read and write trust review.
//! Groups the outcome, context labels, and eligibility flags a review call needs into one value.

use crate::service::trust::{RecipientTrustOutcome, SignerTrustOutcome};

#[derive(Debug, Clone, Copy)]
pub struct SignerTrustLabels<'a> {
    pub context: &'a str,
    pub subject: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct ReadSignerTrustReviewPlan<'a> {
    pub trust_outcome: &'a SignerTrustOutcome,
    pub recipient_trust_outcome: &'a RecipientTrustOutcome,
    pub labels: SignerTrustLabels<'a>,
    pub allow_non_member: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct WriteRecipientTrustReviewPlan<'a> {
    pub signer_trust: Option<(&'a SignerTrustOutcome, SignerTrustLabels<'a>)>,
    pub recipient_trust: &'a RecipientTrustOutcome,
    pub recipient_context_label: &'a str,
}
