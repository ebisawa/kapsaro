// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! doctor command - read-only workspace health diagnostics.

use std::path::PathBuf;

use clap::Args;

use crate::app::doctor::{run_doctor, DoctorRequest};
use crate::cli::common::output::json::doctor::print_doctor_report;
use crate::cli::common::output::text::doctor::format_doctor_report;
use crate::Result;

#[derive(Debug, Clone, Args)]
pub struct DoctorArgs {
    /// Workspace root directory
    #[arg(long, short = 'w')]
    pub workspace: Option<PathBuf>,

    /// Base directory for secretenv local state
    #[arg(long)]
    pub home: Option<PathBuf>,

    /// Member handle for local trust store and self key checks
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_handle: Option<String>,

    /// Show check ids and lower-level reasons
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Enable debug trace logging
    #[arg(long)]
    pub debug: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: DoctorArgs) -> Result<()> {
    let verbose = args.verbose;
    let report = run_doctor(DoctorRequest {
        workspace: args.workspace,
        home: args.home,
        member_handle: args.member_handle,
        debug: args.debug,
        verbose,
    })?;
    if args.json {
        print_doctor_report(&report)?;
    } else {
        print!("{}", format_doctor_report(&report, verbose));
    }
    if report.exit_code() != 0 {
        std::process::exit(report.exit_code());
    }
    Ok(())
}
