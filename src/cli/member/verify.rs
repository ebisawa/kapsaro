// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! `member verify` command.
//! Verifies an incoming member document and offers to approve it.

use crate::cli::common::context::CliContext;
use crate::cli::common::key_context::load_trust_command_session;
use crate::cli::common::output::member::print_member_approval_results;
use crate::cli::common::output::member::print_member_verification_results;
use crate::cli::common::presentation::tty;
use crate::cli::common::trust::{
    confirm_member_key_approval, run_with_trust_command_session_reset_recovery,
};
use kapsaro_core::api::member::approval::{
    evaluate_members_for_approval, save_member_approvals, MemberApprovalSession,
};
use kapsaro_core::api::member::verification::evaluate_members_online;
use kapsaro_core::Error;

use super::VerifyArgs;

pub(crate) fn run(args: VerifyArgs) -> Result<(), Error> {
    if args.approve {
        run_approve(args)
    } else {
        run_verify_only(args)
    }
}

fn run_verify_only(args: VerifyArgs) -> Result<(), Error> {
    let context = CliContext::resolve(&args.common)?;
    let results = evaluate_members_online(&context.workspace_path()?, &args.member_handles)?;
    print_member_verification_results(args.common.json.json, &results)
}

fn run_approve(args: VerifyArgs) -> Result<(), Error> {
    let context = CliContext::resolve(&args.common)?;
    let trust = load_trust_command_session(&context, args.member.member_handle.clone())?;
    let session = MemberApprovalSession::open(context.workspace_path()?, trust)?;
    run_with_trust_command_session_reset_recovery(session.trust_command(), || {
        let mut evaluation = evaluate_members_for_approval(&session, &args.member_handles)?;
        if evaluation.results.is_empty() {
            return print_member_approval_results(args.common.json.json, &evaluation.results);
        }

        review_approval_candidates(&mut evaluation.results)?;

        let has_new_approvals = evaluation.results.iter().any(|r| r.approved);
        if has_new_approvals {
            save_member_approvals(&session, &evaluation)?;
        }

        print_member_approval_results(args.common.json.json, &evaluation.results)
    })
}

fn review_approval_candidates(
    results: &mut [kapsaro_core::api::member::approval::MemberApprovalResult],
) -> Result<(), Error> {
    let requires_review = results.iter().any(|r| r.review_required);
    if !requires_review {
        return Ok(());
    }
    if !tty::is_interactive() {
        return Err(Error::build_invalid_operation_error(
            "member verify --approve requires interactive confirmation".to_string(),
        ));
    }

    for result in results.iter_mut().filter(|r| r.review_required) {
        result.approved = confirm_member_key_approval(result)?;
    }

    Ok(())
}
