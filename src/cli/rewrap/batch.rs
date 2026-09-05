// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Batch rewrap orchestration over explicit service state transitions.
//! Keeps prompts, output, and per-target failure collection in the CLI.

use std::collections::BTreeSet;

use super::promotion::{confirm_incoming_promotions, print_promotion_summary};
use super::RewrapArgs;
use crate::cli::common::output::rewrap::{
    print_rewrap_batch_outcome, RewrapBatchOutcome, RewrapFileFailure, RewrapFileSuccess,
};
use crate::cli::common::output::text::{print_local_state_diagnostics, print_warnings};
use crate::cli::common::presentation::tty;
use crate::cli::common::read_review::{accept_rewrap_non_member, approve_next_rewrap_request};
use kapsaro_core::api::diagnostics::take_local_state_warnings;
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::rewrap::{
    RewrapAcceptance, RewrapOptions, RewrapSession, RewrapSessionDecision, RewrapTarget,
};
use kapsaro_core::api::trust::recovery::evaluate_trust_store_reset;
use kapsaro_core::{Error, Result};

pub(crate) fn run_batch_rewrap(
    args: &RewrapArgs,
    session: &RewrapSession<'_>,
    operation: OperationOptions,
    allow_non_member: bool,
    review_available: bool,
) -> Result<()> {
    let targets = resolve_targets(args, session)?;
    print_warnings(&session.signing_key_warnings()?);
    let promoted = review_and_apply_promotions(session, review_available)?;
    print_warnings(&session.post_promotion_warnings()?);
    let rewrap_options = RewrapOptions::new()
        .with_rotate_key(args.rotate_key)
        .with_clear_disclosure_history(args.clear_disclosure_history)
        .with_operation_options(operation);
    let outcome = execute_targets(session, targets, rewrap_options, allow_non_member)?;
    print_promotion_summary(&promoted, args.common.quiet.quiet);
    print_rewrap_batch_outcome(&outcome, args.common.json.json, args.common.quiet.quiet)
}

fn review_and_apply_promotions(
    session: &RewrapSession<'_>,
    review_available: bool,
) -> Result<Vec<String>> {
    let Some(review) = session.begin_promotion_review(review_available)? else {
        return Ok(Vec::new());
    };
    let accepted = confirm_incoming_promotions(review.view())?;
    let outcome = session.apply_promotions(review, &accepted)?;
    if let Some(trust) = outcome.trust_outcome() {
        print_local_state_diagnostics(trust.warnings());
    }
    Ok(outcome.promoted_member_handles().to_vec())
}

fn resolve_targets(args: &RewrapArgs, session: &RewrapSession<'_>) -> Result<Vec<RewrapTarget>> {
    let targets = if args.targets.is_empty() {
        let listing = session.list_workspace_targets()?;
        print_warnings(listing.warnings());
        listing.into_targets()
    } else {
        args.targets
            .iter()
            .map(RewrapTarget::open)
            .collect::<Result<Vec<_>>>()?
    };
    let targets = collect_unique_targets(targets);
    if targets.is_empty() {
        return Err(Error::build_not_found_error(
            "No encrypted files found for rewrap.\nSearched: workspace secrets/\nAction: Pass --target <path> for an explicit file."
                .to_string(),
        ));
    }
    Ok(targets)
}

fn collect_unique_targets(targets: Vec<RewrapTarget>) -> Vec<RewrapTarget> {
    let keep = {
        let mut seen = BTreeSet::new();
        targets
            .iter()
            .map(|target| seen.insert(target))
            .collect::<Vec<_>>()
    };
    targets
        .into_iter()
        .zip(keep)
        .filter_map(|(target, keep)| keep.then_some(target))
        .collect()
}

fn execute_targets(
    session: &RewrapSession<'_>,
    targets: Vec<RewrapTarget>,
    options: RewrapOptions,
    allow_non_member: bool,
) -> Result<RewrapBatchOutcome> {
    let mut outcome = RewrapBatchOutcome {
        processed_files: Vec::new(),
        failed_files: Vec::new(),
    };
    for target in targets {
        let output_path = target.path().to_path_buf();
        match execute_target(session, target, options, allow_non_member) {
            Ok(()) => outcome
                .processed_files
                .push(RewrapFileSuccess { output_path }),
            Err(error) => {
                if evaluate_trust_store_reset(&error).is_some() {
                    return Err(error);
                }
                outcome.failed_files.push(RewrapFileFailure {
                    output_path,
                    error_message: error.format_user_message().to_string(),
                });
            }
        }
        print_local_state_diagnostics(&take_local_state_warnings());
    }
    Ok(outcome)
}

fn execute_target(
    session: &RewrapSession<'_>,
    target: RewrapTarget,
    options: RewrapOptions,
    allow_non_member: bool,
) -> Result<()> {
    let mut decision = session.begin_rewrap(target, options, allow_non_member)?;
    let mut acceptance: Option<RewrapAcceptance> = None;
    loop {
        decision = match decision {
            RewrapSessionDecision::Authorized(authorized) => return authorized.publish(),
            RewrapSessionDecision::ReviewRequired(mut review) => {
                if review.non_member_signer().is_some() {
                    if !tty::is_interactive() {
                        return Err(Error::build_verification_error(
                            "E_TRUST_NON_MEMBER",
                            "Non-member signer acceptance requires an interactive terminal.",
                        ));
                    }
                    acceptance = Some(accept_rewrap_non_member(&mut review)?);
                } else if !approve_next_rewrap_request(session, &mut review)? {
                    return Err(Error::build_verification_error(
                        "E_TRUST_REJECTED",
                        "Rewrap trust review could not be completed.",
                    ));
                }
                session.resume_rewrap(review, options, acceptance.take())?
            }
        };
    }
}
