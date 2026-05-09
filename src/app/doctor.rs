// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read-only workspace health diagnostics.

pub(crate) mod artifacts;
pub(crate) mod ci;
pub(crate) mod local_state;
pub(crate) mod members;
pub(crate) mod types;
pub(crate) mod workspace;

use std::path::PathBuf;

use crate::app::context::options::CommonCommandOptions;
use crate::Result;

use self::types::DoctorReport;

#[derive(Debug, Clone)]
pub(crate) struct DoctorRequest {
    pub(crate) workspace: Option<PathBuf>,
    pub(crate) home: Option<PathBuf>,
    pub(crate) member_handle: Option<String>,
    pub(crate) debug: bool,
    pub(crate) verbose: bool,
}

impl DoctorRequest {
    pub(crate) fn common_options(&self) -> CommonCommandOptions {
        CommonCommandOptions {
            home: self.home.clone(),
            identity: None,
            debug: self.debug,
            verbose: self.verbose,
            workspace: self.workspace.clone(),
            ssh_signing_method: None,
        }
    }
}

pub(crate) fn run_doctor(request: DoctorRequest) -> Result<DoctorReport> {
    let options = request.common_options();
    let workspace_state = workspace::diagnose_workspace(&options)?;
    let mut report = DoctorReport::new(workspace_state.workspace_display());
    report.extend(workspace_state.checks);
    let local_state =
        local_state::diagnose_local_state(&options, request.member_handle.as_deref())?;
    report.extend(local_state.checks);

    if let Some(workspace_root) = workspace_state
        .workspace_root
        .as_ref()
        .filter(|_| workspace_state.structure_ok)
    {
        report.extend(members::diagnose_members(workspace_root, options.debug)?);
        report.extend(local_state::diagnose_trust_store(
            &options,
            request.member_handle.as_deref(),
            workspace_root,
        )?);
        report.extend(artifacts::diagnose_artifacts(
            &options,
            request.member_handle.as_deref(),
            workspace_root,
        )?);
    }

    report.extend(ci::diagnose_ci_readiness(&options));
    Ok(report)
}

#[cfg(test)]
#[path = "../../tests/unit/internal/app_doctor_workspace_test.rs"]
mod tests;
