// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! doctor command - read-only workspace health diagnostics.

use clap::Args;

use crate::cli::common::output::json::doctor::print_doctor_report;
use crate::cli::common::output::text::doctor::format_doctor_report;
use crate::cli::common::{context::CliContext, env_mode::capture_doctor_ci_readiness};
use crate::cli::options::{DoctorOutputOptions, MemberHandleOption};
use kapsaro_core::api::doctor::{execute_doctor_command, DoctorCiReadiness, DoctorRequest};
use kapsaro_core::Result;

#[derive(Debug, Clone, Args)]
pub(crate) struct DoctorArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: DoctorOutputOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,
}

pub(crate) fn run(args: DoctorArgs) -> Result<i32> {
    let verbose = args.common.verbose.verbose;
    let context = CliContext::resolve_doctor(&args.common);
    let ci = capture_doctor_ci_readiness(&context);
    let workspaces = context.doctor_workspace_resolutions();
    // Environment-variable key mode must not open the local state home just to
    // name an owner, so only an explicitly given handle is used there.
    let member_handle = match &ci {
        DoctorCiReadiness::Active { .. } => Ok(args.member.member_handle.clone()),
        DoctorCiReadiness::Inactive => context.configured_member_handle(args.member.member_handle),
    };
    let report = execute_doctor_command(DoctorRequest {
        local_state: context.into_optional_local_state().and_then(|state| {
            state.ok_or_else(|| {
                kapsaro_core::Error::build_config_error("Local state home could not be resolved")
            })
        }),
        workspaces,
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
