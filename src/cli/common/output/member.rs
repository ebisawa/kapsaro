// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member command output dispatchers.

pub(crate) mod view;

pub(crate) use view::{
    MemberApprovalResultsView, MemberListView, MemberShowView, MemberVerificationResultsView,
};

use crate::app::member::approval::MemberApprovalResult;
use crate::app::member::types::{MemberListResult, MemberShowResult, MemberVerificationResult};
use crate::cli::common::output::json::member::{
    print_empty_member_list as print_empty_member_list_json,
    print_member_approval_results as print_member_approval_results_json,
    print_member_list as print_member_list_json,
    print_member_verification_results as print_member_verification_results_json,
};
use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::text::member::{
    print_empty_member_approval_results, print_empty_member_list as print_empty_member_list_text,
    print_empty_member_verification_results,
    print_member_approval_results as print_member_approval_results_text, print_member_sections,
    print_member_show as print_member_show_text,
    print_member_verification_results as print_member_verification_results_text,
};
use crate::cli::common::output::{
    print_empty_or_json_or_text, print_empty_or_json_or_text_with_warnings,
    print_json_or_text_with_warnings,
};
use crate::Result;

pub(crate) fn print_member_verification_results(
    json_output: bool,
    results: &[MemberVerificationResult],
) -> Result<()> {
    let view = view::build_member_verification_results_view(results);
    print_empty_or_json_or_text(
        json_output,
        view.results.is_empty(),
        || print_member_verification_results_json(&view),
        print_empty_member_verification_results,
        || print_member_verification_results_json(&view),
        || print_member_verification_results_text(&view),
    )
}

pub(crate) fn print_member_approval_results(
    json_output: bool,
    results: &[MemberApprovalResult],
) -> Result<()> {
    let view = view::build_member_approval_results_view(results);
    print_empty_or_json_or_text(
        json_output,
        view.results.is_empty(),
        || print_member_approval_results_json(&view),
        print_empty_member_approval_results,
        || print_member_approval_results_json(&view),
        || print_member_approval_results_text(&view),
    )
}

pub(crate) fn print_member_list(json_output: bool, result: &MemberListResult) -> Result<()> {
    let view = view::build_member_list_view(result);

    print_empty_or_json_or_text_with_warnings(
        json_output,
        view.active.is_empty() && view.incoming.is_empty(),
        view.warnings,
        print_empty_member_list_json,
        print_empty_member_list_text,
        || print_member_list_json(&view),
        || print_member_sections(&view),
    )
}

pub(crate) fn print_member_show(json_output: bool, result: &MemberShowResult) -> Result<()> {
    let view = view::build_member_show_view(result);
    print_json_or_text_with_warnings(
        json_output,
        view.verification_warnings,
        || print_json_output(view.document),
        || print_member_show_text(&view),
    )
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/cli_common_output_member_test.rs"]
mod tests;
