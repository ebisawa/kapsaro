// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! doctor command - read-only workspace health diagnostics.

use clap::Args;

use crate::cli::common::output::json::doctor::print_doctor_report;
use crate::cli::common::output::text::doctor::format_doctor_report;
use crate::cli::common::{context::CliContext, env_mode::capture_doctor_ci_readiness};
use crate::cli::options::{MemberHandleOption, WorkspaceOutputOptions};
use kapsaro_core::api::doctor::{execute_doctor_command, DoctorCiReadiness, DoctorRequest};
use kapsaro_core::Result;

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
    let context = CliContext::resolve(&args.common)?;
    let ci = capture_doctor_ci_readiness();
    let workspace = context.doctor_workspace_resolution();
    let member_handle = match &ci {
        DoctorCiReadiness::Active { .. } => args.member.member_handle.clone(),
        DoctorCiReadiness::Inactive => {
            context.resolve_member_handle_override(args.member.member_handle)?
        }
    };
    let report = execute_doctor_command(DoctorRequest {
        base_dir: context.base_dir()?.to_path_buf(),
        workspace,
        member_handle,
        ci,
    })?;
    if args.common.json.json {
        print_doctor_report(&report)?;
    } else {
        print!("{}", format_doctor_report(&report, verbose));
    }
    Ok(report.exit_code())
}
