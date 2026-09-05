// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact output recipient-set review helper.
//! Keeps service operations from duplicating artifact evidence extraction.

use crate::feature::artifact::artifact_recipient_evidence;
use crate::format::content::EncContent;
use crate::service::trust::{ArtifactRecipientTrustOutcome, TrustCommandSession, TrustContext};
use crate::Result;

use super::execution::{review_artifact_recipient_set_output, ArtifactRecipientSetReviewInput};

pub struct ArtifactOutputRecipientSetReviewInput<'a> {
    pub session: &'a TrustCommandSession,
    pub trust_ctx: &'a TrustContext,
    pub content: &'a EncContent,
    pub context_label: &'a str,
}

pub fn review_artifact_output_recipient_set<ConfirmRecipientSet>(
    review: ArtifactOutputRecipientSetReviewInput<'_>,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<()>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let evidence = artifact_recipient_evidence(review.content)?;
    review_artifact_recipient_set_output(
        review.session,
        ArtifactRecipientSetReviewInput {
            trust_ctx: review.trust_ctx,
            recipient_set: &evidence.recipient_set,
            context_label: review.context_label,
        },
        confirm_recipient_set,
    )
}
