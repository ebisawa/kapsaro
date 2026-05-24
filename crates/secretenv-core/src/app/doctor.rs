// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read-only workspace health diagnostics.

pub mod artifacts;
pub mod ci;
pub mod local_state;
pub mod members;
pub mod types;
pub mod workspace;

use std::path::PathBuf;

use crate::app::context::options::CommonCommandOptions;
use crate::Result;
use tracing::debug;

use self::types::DoctorReport;

#[derive(Debug, Clone)]
pub struct DoctorRequest {
    pub workspace: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub member_handle: Option<String>,
    pub debug: bool,
    pub verbose: bool,
}

impl DoctorRequest {
    pub fn common_options(&self) -> CommonCommandOptions {
        CommonCommandOptions {
            home: self.home.clone(),
            identity: None,
            debug: self.debug,
            verbose: self.verbose,
            workspace: self.workspace.clone(),
            ssh_signing_method: None,
            allow_expired_key: false,
        }
    }
}

pub fn execute_doctor_command(request: DoctorRequest) -> Result<DoctorReport> {
    let options = request.common_options();
    if options.debug {
        debug!(
            "[DOCTOR] start: workspace={}, home={}, member_handle={}",
            request
                .workspace
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "(auto)".to_string()),
            request
                .home
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "(default)".to_string()),
            request.member_handle.as_deref().unwrap_or("(auto)")
        );
    }
    let workspace_state = workspace::check_workspace(&options)?;
    let mut report = DoctorReport::new(workspace_state.workspace_display());
    report.extend(workspace_state.checks);
    log_doctor_count(&options, "workspace", report.checks().len());
    let local_state = local_state::check_local_state(&options, request.member_handle.as_deref())?;
    let local_count = local_state.checks.len();
    report.extend(local_state.checks);
    log_doctor_count(&options, "local_state", local_count);

    if let Some(workspace_root) = workspace_state
        .workspace_root
        .as_ref()
        .filter(|_| workspace_state.structure_ok)
    {
        let checks = members::check_members(workspace_root, options.debug)?;
        log_doctor_count(&options, "members", checks.len());
        report.extend(checks);
        let checks = local_state::check_trust_store(
            &options,
            request.member_handle.as_deref(),
            workspace_root,
        )?;
        log_doctor_count(&options, "trust_store", checks.len());
        report.extend(checks);
        let checks =
            artifacts::check_artifacts(&options, request.member_handle.as_deref(), workspace_root)?;
        log_doctor_count(&options, "artifacts", checks.len());
        report.extend(checks);
    }

    let checks = ci::check_ci_readiness(&options);
    log_doctor_count(&options, "ci_readiness", checks.len());
    report.extend(checks);
    if options.debug {
        debug!(
            "[DOCTOR] complete: overall={}, checks={}",
            report.overall_status().as_str(),
            report.checks().len()
        );
    }
    Ok(report)
}

fn log_doctor_count(options: &CommonCommandOptions, category: &str, count: usize) {
    if options.debug {
        debug!("[DOCTOR] category={} checks={}", category, count);
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/app_doctor_workspace_test.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/internal/app_doctor_diagnostics_test.rs"]
mod diagnostics_tests;
