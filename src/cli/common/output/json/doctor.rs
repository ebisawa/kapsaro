// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON rendering for the doctor command.
//! Converts the diagnostic report into the serializable shape the CLI prints.

use serde::Serialize;

use crate::cli::common::output::json::print_json_output;
use kapsaro_core::api::doctor::types::{
    DoctorCategory, DoctorCheck, DoctorReason, DoctorReport, DoctorStatus,
};
use kapsaro_core::Result;

#[derive(Serialize)]
struct DoctorReportOutput<'a> {
    status: &'static str,
    exit_code: i32,
    workspace: &'a str,
    summary: DoctorSummaryOutput,
    next_actions: Vec<&'a str>,
    checks: Vec<DoctorCheckOutput<'a>>,
}

#[derive(Serialize)]
struct DoctorSummaryOutput {
    ok: usize,
    warn: usize,
    fail: usize,
    skip: usize,
    artifacts_checked: usize,
    rewrap_recommended: usize,
}

#[derive(Serialize)]
struct DoctorCheckOutput<'a> {
    id: &'a str,
    category: &'static str,
    status: &'static str,
    subject: &'a str,
    message: &'a str,
    reason: Option<&'a str>,
    /// The names a reason was built from, kept apart.
    ///
    /// Entry names come from the filesystem, so one of them may hold whatever
    /// separator a joined line would use. A consumer reads them from here
    /// instead, and `reason` stays empty for such a check so nothing invites
    /// splitting a line that cannot be split back.
    reason_entries: Option<&'a [String]>,
    next_action: Option<&'a str>,
    rule: Option<&'a str>,
}

pub(crate) fn print_doctor_report(report: &DoctorReport) -> Result<()> {
    let output = DoctorReportOutput {
        status: status_name(report.overall_status()),
        exit_code: report.exit_code(),
        workspace: report.workspace_display(),
        summary: DoctorSummaryOutput {
            ok: report.count(DoctorStatus::Ok),
            warn: report.count(DoctorStatus::Warn),
            fail: report.count(DoctorStatus::Fail),
            skip: report.count(DoctorStatus::Skip),
            artifacts_checked: report.artifact_count(),
            rewrap_recommended: report.rewrap_recommended_count(),
        },
        next_actions: report.next_actions(),
        checks: report
            .checks()
            .iter()
            .map(DoctorCheckOutput::from)
            .collect(),
    };
    print_json_output(&output)
}

impl<'a> From<&'a DoctorCheck> for DoctorCheckOutput<'a> {
    fn from(check: &'a DoctorCheck) -> Self {
        let (reason, reason_entries) = split_reason(check.reason.as_ref());
        Self {
            id: check.id,
            category: category_name(check.category),
            status: status_name(check.status),
            subject: check.subject.as_str(),
            message: &check.message,
            reason,
            reason_entries,
            next_action: check.next_action.as_deref(),
            rule: check.rule.as_deref(),
        }
    }
}

/// Route a reason to the field that carries it without losing its boundaries.
fn split_reason(reason: Option<&DoctorReason>) -> (Option<&str>, Option<&[String]>) {
    match reason {
        None => (None, None),
        Some(DoctorReason::Message(message)) => (Some(message.as_str()), None),
        Some(DoctorReason::Names(names)) => (None, Some(names.as_slice())),
    }
}

fn status_name(status: DoctorStatus) -> &'static str {
    match status {
        DoctorStatus::Ok => "ok",
        DoctorStatus::Warn => "warn",
        DoctorStatus::Fail => "fail",
        DoctorStatus::Skip => "skip",
    }
}

fn category_name(category: DoctorCategory) -> &'static str {
    match category {
        DoctorCategory::Workspace => "workspace",
        DoctorCategory::MembersActive => "members_active",
        DoctorCategory::MembersIncoming => "members_incoming",
        DoctorCategory::LocalState => "local_state",
        DoctorCategory::LocalKeystore => "local_keystore",
        DoctorCategory::LocalTrustStore => "local_trust_store",
        DoctorCategory::Artifacts => "artifacts",
        DoctorCategory::CiReadiness => "ci_readiness",
    }
}
