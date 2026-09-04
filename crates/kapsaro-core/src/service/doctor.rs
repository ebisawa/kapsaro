// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read-only workspace health diagnostics for API callers.

pub mod artifacts;
pub mod ci;
pub mod local_state;
pub mod members;
pub mod types;
pub mod workspace;

use std::path::PathBuf;

use crate::support::fs::anchor::AnchoredDir;
use crate::support::warning::clear_local_state_warnings;
use crate::Result;
use tracing::debug;

use self::types::DoctorReport;

#[derive(Debug)]
pub struct DoctorRequest {
    pub base_dir: PathBuf,
    pub workspace: DoctorWorkspaceResolution,
    pub member_handle: Option<String>,
    pub ci: ci::DoctorCiReadiness,
}

/// Workspace resolution completed by the caller before diagnostics begin.
#[derive(Debug)]
pub enum DoctorWorkspaceResolution {
    /// An absolute workspace path selected from the named source.
    Selection {
        path: PathBuf,
        source: DoctorWorkspaceSource,
    },
    /// No workspace was selected by any configured source or auto-detection.
    Unresolved,
    /// Workspace resolution failed, preserved so diagnostics can report it.
    Failure(crate::Error),
}

/// Origin of the workspace path selected by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorWorkspaceSource {
    Cli,
    Environment,
    Config,
    AutoDetect,
}

impl DoctorWorkspaceSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "CLI option",
            Self::Environment => "environment variable",
            Self::Config => "global configuration",
            Self::AutoDetect => "auto-detection",
        }
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
    log_doctor_start(&request);
    let allow_local_owner_fallback = matches!(&request.ci, ci::DoctorCiReadiness::Inactive);

    let mut workspace_state = workspace::check_workspace(&request.base_dir, &request.workspace);
    let mut report = DoctorReport::new(workspace_state.workspace_display());
    report.extend(std::mem::take(&mut workspace_state.checks));
    log_doctor_count("workspace", report.checks().len());

    let local_state = extend_local_state_checks(
        &mut report,
        &request.base_dir,
        request.member_handle.as_deref(),
        allow_local_owner_fallback,
    )?;
    if let Some(workspace_dir) = workspace_state.scoped_workspace() {
        extend_workspace_scoped_checks(
            &mut report,
            &request.base_dir,
            workspace_dir,
            &local_state,
        )?;
    }
    extend_ci_readiness_checks(&mut report, request.ci);
    log_doctor_complete(&report);
    Ok(report)
}

fn log_doctor_start(request: &DoctorRequest) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    debug!(
        "[DOCTOR] start: workspace={}, home={}, member_handle={}",
        format_workspace_resolution(&request.workspace),
        request.base_dir.display(),
        request.member_handle.as_deref().unwrap_or("(unresolved)")
    );
}

fn format_workspace_resolution(workspace: &DoctorWorkspaceResolution) -> String {
    match workspace {
        DoctorWorkspaceResolution::Selection { path, .. } => path.display().to_string(),
        DoctorWorkspaceResolution::Unresolved => "(unresolved)".to_string(),
        DoctorWorkspaceResolution::Failure(_) => "(resolution failed)".to_string(),
    }
}

fn extend_local_state_checks(
    report: &mut DoctorReport,
    base_dir: &std::path::Path,
    member_handle: Option<&str>,
    allow_owner_fallback: bool,
) -> Result<local_state::LocalStateDiagnostics> {
    let mut local_state =
        local_state::check_local_state(base_dir, member_handle, allow_owner_fallback)?;
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
    base_dir: &std::path::Path,
    workspace_dir: &AnchoredDir,
    local_state: &local_state::LocalStateDiagnostics,
) -> Result<()> {
    extend_member_checks(report, workspace_dir)?;
    extend_trust_store_checks(report, base_dir, workspace_dir, local_state)?;
    extend_artifact_checks(report, workspace_dir)?;
    Ok(())
}

fn extend_member_checks(report: &mut DoctorReport, workspace_dir: &AnchoredDir) -> Result<()> {
    let checks = members::check_members(workspace_dir)?;
    log_doctor_count("members", checks.len());
    report.extend(checks);
    Ok(())
}

fn extend_trust_store_checks(
    report: &mut DoctorReport,
    base_dir: &std::path::Path,
    workspace_dir: &AnchoredDir,
    local_state: &local_state::LocalStateDiagnostics,
) -> Result<()> {
    let checks = local_state::check_trust_store(
        base_dir,
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

fn extend_ci_readiness_checks(report: &mut DoctorReport, input: ci::DoctorCiReadiness) {
    let checks = ci::check_ci_readiness(input);
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
#[path = "../../tests/unit/internal/service_doctor_test.rs"]
mod service_doctor_test;
