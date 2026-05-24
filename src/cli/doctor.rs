// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! doctor command - read-only workspace health diagnostics.

use clap::Args;

use crate::cli::common::output::json::doctor::print_doctor_report;
use crate::cli::common::output::text::doctor::format_doctor_report;
use crate::cli::options::{MemberHandleOption, WorkspaceOutputOptions};
use secretenv_core::cli_api::app::doctor::{execute_doctor_command, DoctorRequest};
use secretenv_core::Result;

#[derive(Debug, Clone, Args)]
pub(crate) struct DoctorArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: WorkspaceOutputOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,
}

pub(crate) fn run(args: DoctorArgs) -> Result<i32> {
    let verbose = args.common.verbose.verbose;
    let report = execute_doctor_command(DoctorRequest {
        workspace: args.common.workspace.workspace,
        home: args.common.home.home,
        member_handle: args.member.member_handle,
        debug: args.common.debug.debug,
        verbose,
    })?;
    if args.common.json.json {
        print_doctor_report(&report)?;
    } else {
        print!("{}", format_doctor_report(&report, verbose));
    }
    Ok(report.exit_code())
}
