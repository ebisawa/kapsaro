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
use crate::io::workspace::detection::WorkspaceRoot;
use crate::Result;
use tracing::debug;

use self::types::DoctorReport;

#[derive(Debug, Clone)]
pub struct DoctorRequest {
    pub workspace: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub member_handle: Option<String>,
    pub verbose: bool,
}

impl DoctorRequest {
    pub fn common_options(&self) -> CommonCommandOptions {
        CommonCommandOptions {
            home: self.home.clone(),
            identity: None,
            verbose: self.verbose,
            workspace: self.workspace.clone(),
            ssh_signing_method: None,
            allow_expired_key: false,
            allow_non_member: false,
        }
    }
}

pub fn execute_doctor_command(request: DoctorRequest) -> Result<DoctorReport> {
    let options = request.common_options();
    log_doctor_start(&request);

    let workspace_state = workspace::check_workspace(&options)?;
    let mut report = DoctorReport::new(workspace_state.workspace_display());
    report.extend(workspace_state.checks);
    log_doctor_count("workspace", report.checks().len());

    extend_local_state_checks(&mut report, &options, request.member_handle.as_deref())?;
    if let Some(workspace_root) = workspace_state
        .workspace_root
        .as_ref()
        .filter(|_| workspace_state.structure_ok)
    {
        extend_workspace_scoped_checks(
            &mut report,
            &options,
            request.member_handle.as_deref(),
            workspace_root,
        )?;
    }
    extend_ci_readiness_checks(&mut report);
    log_doctor_complete(&report);
    Ok(report)
}

fn log_doctor_start(request: &DoctorRequest) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
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

fn extend_local_state_checks(
    report: &mut DoctorReport,
    options: &CommonCommandOptions,
    member_handle: Option<&str>,
) -> Result<()> {
    let local_state = local_state::check_local_state(options, member_handle)?;
    let local_count = local_state.checks.len();
    report.extend(local_state.checks);
    log_doctor_count("local_state", local_count);
    Ok(())
}

fn extend_workspace_scoped_checks(
    report: &mut DoctorReport,
    options: &CommonCommandOptions,
    member_handle: Option<&str>,
    workspace_root: &WorkspaceRoot,
) -> Result<()> {
    extend_member_checks(report, workspace_root)?;
    extend_trust_store_checks(report, options, member_handle, workspace_root)?;
    extend_artifact_checks(report, member_handle, workspace_root)?;
    Ok(())
}

fn extend_member_checks(report: &mut DoctorReport, workspace_root: &WorkspaceRoot) -> Result<()> {
    let checks = members::check_members(workspace_root)?;
    log_doctor_count("members", checks.len());
    report.extend(checks);
    Ok(())
}

fn extend_trust_store_checks(
    report: &mut DoctorReport,
    options: &CommonCommandOptions,
    member_handle: Option<&str>,
    workspace_root: &WorkspaceRoot,
) -> Result<()> {
    let checks = local_state::check_trust_store(options, member_handle, workspace_root)?;
    log_doctor_count("trust_store", checks.len());
    report.extend(checks);
    Ok(())
}

fn extend_artifact_checks(
    report: &mut DoctorReport,
    member_handle: Option<&str>,
    workspace_root: &WorkspaceRoot,
) -> Result<()> {
    let checks = artifacts::check_artifacts(member_handle, workspace_root)?;
    log_doctor_count("artifacts", checks.len());
    report.extend(checks);
    Ok(())
}

fn extend_ci_readiness_checks(report: &mut DoctorReport) {
    let checks = ci::check_ci_readiness();
    log_doctor_count("ci_readiness", checks.len());
    report.extend(checks);
}

fn log_doctor_complete(report: &DoctorReport) {
    debug!(
        "[DOCTOR] complete: overall={}, checks={}",
        report.overall_status().as_str(),
        report.checks().len()
    );
}

fn log_doctor_count(category: &str, count: usize) {
    debug!("[DOCTOR] category={} checks={}", category, count);
}

#[cfg(test)]
#[path = "../../tests/unit/internal/app_doctor_workspace_test.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/internal/app_doctor_diagnostics_test.rs"]
mod diagnostics_tests;
