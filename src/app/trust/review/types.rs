// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::trust::{RecipientTrustOutcome, SignerTrustOutcome};

#[derive(Debug, Clone, Copy)]
pub(crate) struct SignerTrustLabels<'a> {
    pub(crate) context: &'a str,
    pub(crate) subject: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadSignerTrustReviewPlan<'a> {
    pub(crate) trust_outcome: &'a SignerTrustOutcome,
    pub(crate) recipient_trust_outcome: &'a RecipientTrustOutcome,
    pub(crate) labels: SignerTrustLabels<'a>,
    pub(crate) allow_non_member: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WriteRecipientTrustReviewPlan<'a> {
    pub(crate) signer_trust: Option<(&'a SignerTrustOutcome, SignerTrustLabels<'a>)>,
    pub(crate) recipient_trust: &'a RecipientTrustOutcome,
    pub(crate) recipient_context_label: &'a str,
}
