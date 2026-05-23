// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli::common::command::{
    resolve_options, resolve_trust_store_owner_member, resolve_write_execution_input,
};
use crate::cli::common::output::member::print_member_approval_results;
use crate::cli::common::output::member::print_member_verification_results;
use crate::cli::common::output::text;
use crate::cli::common::trust::{confirm_member_key_approval, run_with_trust_store_reset_recovery};
use secretenv_core::cli_api::app::member::approval::{
    evaluate_members_for_approval, save_member_approvals,
};
use secretenv_core::cli_api::app::member::verification::verify_members;
use secretenv_core::cli_api::app::trust::TrustApprovalCandidate;
use secretenv_core::cli_api::presentation::tty;
use secretenv_core::Error;

use super::VerifyArgs;

pub(crate) fn run(args: VerifyArgs) -> Result<(), Error> {
    if args.approve {
        run_approve(args)
    } else {
        run_verify_only(args)
    }
}

fn run_verify_only(args: VerifyArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let results = verify_members(&options, &args.member_handles, args.common.debug.debug)?;
    print_member_verification_results(args.common.json.json, &results)
}

fn run_approve(args: VerifyArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member.member_handle.clone()),
        || {
            let execution =
                resolve_write_execution_input(&options, args.member.member_handle.clone())?;

            let evaluation = evaluate_members_for_approval(
                &options,
                &args.member_handles,
                &execution.member_handle,
            )?;
            text::print_warnings(&evaluation.warnings);
            let mut results = evaluation.results;

            if results.is_empty() {
                return print_member_approval_results(args.common.json.json, &results);
            }

            review_approval_candidates(&mut results)?;

            let has_new_approvals = results.iter().any(|r| r.approved);
            if has_new_approvals {
                let commit_result = save_member_approvals(&options, &results, &execution)?;
                text::print_warnings(&commit_result.warnings);
            }

            print_member_approval_results(args.common.json.json, &results)
        },
    )
}

fn review_approval_candidates(
    results: &mut [secretenv_core::cli_api::app::member::approval::MemberApprovalResult],
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
        let candidate = TrustApprovalCandidate::from(&*result);
        result.approved = confirm_member_key_approval(&candidate, "member verify")?;
    }

    Ok(())
}
