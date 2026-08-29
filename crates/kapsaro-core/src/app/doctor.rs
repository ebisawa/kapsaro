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
use crate::support::fs::anchor::AnchoredDir;
use crate::support::warning::clear_local_state_warnings;
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
        CommonCommandOptions::new()
            .with_home(self.home.clone())
            .with_verbose(self.verbose)
            .with_workspace(self.workspace.clone())
    }
}

/// Run every diagnostic and hand back the report.
///
/// The collected warnings are dropped on the way out whichever way the run
/// ends. A check that fails early leaves the same violations behind, and a
/// long-lived caller would then see them again on its next command.
pub fn execute_doctor_command(request: DoctorRequest) -> Result<DoctorReport> {
    let report = build_doctor_report(request);
    // The same violations are already reported as findings of this command, so
    // the collected warnings would name every one of them a second time.
    clear_local_state_warnings();
    report
}

fn build_doctor_report(request: DoctorRequest) -> Result<DoctorReport> {
    let options = request.common_options();
    log_doctor_start(&request);

    let mut workspace_state = workspace::check_workspace(&options)?;
    let mut report = DoctorReport::new(workspace_state.workspace_display());
    report.extend(std::mem::take(&mut workspace_state.checks));
    log_doctor_count("workspace", report.checks().len());

    let local_state =
        extend_local_state_checks(&mut report, &options, request.member_handle.as_deref())?;
    if let Some(workspace_dir) = workspace_state.scoped_workspace() {
        extend_workspace_scoped_checks(&mut report, &options, workspace_dir, &local_state)?;
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
) -> Result<local_state::LocalStateDiagnostics> {
    let mut local_state = local_state::check_local_state(options, member_handle)?;
    let local_count = local_state.checks.len();
    report.extend(std::mem::take(&mut local_state.checks));
    log_doctor_count("local_state", local_count);
    Ok(local_state)
}

/// Run every check that is about the workspace, all against the one descriptor
/// this run bound to.
///
/// Reading each of them from the workspace path again would let a path
/// repointed mid-run put two different trees into one report, where the findings
/// on one contradict the repair advice given for the other.
fn extend_workspace_scoped_checks(
    report: &mut DoctorReport,
    options: &CommonCommandOptions,
    workspace_dir: &AnchoredDir,
    local_state: &local_state::LocalStateDiagnostics,
) -> Result<()> {
    extend_workspace_locking_checks(report, workspace_dir);
    extend_member_checks(report, workspace_dir)?;
    extend_trust_store_checks(report, options, workspace_dir, local_state)?;
    extend_artifact_checks(report, workspace_dir)?;
    Ok(())
}

/// What a lock on the workspace root excludes.
///
/// A workspace whose structure never resolved is not measured, and says so by
/// carrying no check of its own. The local state root is measured on every run,
/// so an operator is told what locking is worth on their storage either way.
fn extend_workspace_locking_checks(report: &mut DoctorReport, workspace_dir: &AnchoredDir) {
    let checks = local_state::locking::check_workspace_locking(workspace_dir);
    log_doctor_count("workspace_locking", checks.len());
    report.extend(checks);
}

fn extend_member_checks(report: &mut DoctorReport, workspace_dir: &AnchoredDir) -> Result<()> {
    let checks = members::check_members(workspace_dir)?;
    log_doctor_count("members", checks.len());
    report.extend(checks);
    Ok(())
}

fn extend_trust_store_checks(
    report: &mut DoctorReport,
    options: &CommonCommandOptions,
    workspace_dir: &AnchoredDir,
    local_state: &local_state::LocalStateDiagnostics,
) -> Result<()> {
    let checks = local_state::check_trust_store(
        options,
        local_state.owner.as_ref(),
        workspace_dir,
        local_state.keystore.as_ref(),
        &local_state.home,
    )?;
    log_doctor_count("trust_store", checks.len());
    report.extend(checks);
    Ok(())
}

fn extend_artifact_checks(report: &mut DoctorReport, workspace_dir: &AnchoredDir) -> Result<()> {
    let checks = artifacts::check_artifacts(workspace_dir)?;
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
