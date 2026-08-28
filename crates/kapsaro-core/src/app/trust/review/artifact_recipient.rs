// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact output recipient-set review helper.
//! Keeps app commands from duplicating artifact evidence extraction.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::{ArtifactRecipientTrustOutcome, CommandCapability, TrustContext};
use crate::feature::artifact::artifact_recipient_evidence;
use crate::format::content::EncContent;
use crate::Result;

use super::execution::{
    review_artifact_recipient_set_output, ArtifactRecipientSetReviewInput, TrustExecutionContext,
};

struct ArtifactContentReviewInput<'a> {
    trust_ctx: &'a TrustContext,
    content: &'a EncContent,
    capability: CommandCapability,
    context_label: &'a str,
}

pub struct ArtifactOutputRecipientSetReviewInput<'a> {
    pub options: &'a CommonCommandOptions,
    pub execution: &'a ExecutionContext,
    pub trust_ctx: &'a TrustContext,
    pub content: &'a EncContent,
    pub capability: CommandCapability,
    pub context_label: &'a str,
}

pub fn review_artifact_output_recipient_set<ConfirmRecipientSet>(
    review: ArtifactOutputRecipientSetReviewInput<'_>,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<()>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    review_artifact_content_recipient_set_output(
        TrustExecutionContext {
            options: review.options,
            execution: review.execution,
        },
        ArtifactContentReviewInput {
            trust_ctx: review.trust_ctx,
            content: review.content,
            capability: review.capability,
            context_label: review.context_label,
        },
        confirm_recipient_set,
    )
}

fn review_artifact_content_recipient_set_output<ConfirmRecipientSet>(
    execution: TrustExecutionContext<'_>,
    review: ArtifactContentReviewInput<'_>,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<()>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let evidence = artifact_recipient_evidence(review.content)?;
    review_artifact_recipient_set_output(
        execution,
        ArtifactRecipientSetReviewInput {
            trust_ctx: review.trust_ctx,
            recipient_set: &evidence.recipient_set,
            capability: review.capability,
            context_label: review.context_label,
        },
        confirm_recipient_set,
    )
}
