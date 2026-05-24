// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderer for doctor reports.

use console::Style;

use crate::cli::common::output::text::layout;
use secretenv_core::cli_api::app::doctor::types::{DoctorCheck, DoctorReport, DoctorStatus};

pub(crate) fn format_doctor_report(report: &DoctorReport, verbose: bool) -> String {
    let mut out = String::new();
    push_summary(&mut out, report);
    push_next_actions(&mut out, report);
    push_findings(&mut out, report, verbose);
    push_healthy_areas(&mut out, report);
    push_details(&mut out, report);
    out
}

fn push_summary(out: &mut String, report: &DoctorReport) {
    out.push_str(&format!("Status: {}\n", report.overall_status().as_str()));
    push_wrapped_value(out, "Workspace: ", report.workspace_display());
    out.push_str(&format!(
        "Checks: {} OK, {} WARN, {} FAIL, {} SKIP\n",
        report.count(DoctorStatus::Ok),
        report.count(DoctorStatus::Warn),
        report.count(DoctorStatus::Fail),
        report.count(DoctorStatus::Skip)
    ));
    out.push_str(&format!(
        "Artifacts: {} checked, {} rewrap recommended\n",
        report.artifact_count(),
        report.rewrap_recommended_count()
    ));
    if report.overall_status() == DoctorStatus::Ok {
        out.push_str("\nNo action needed.\n");
    }
}

fn push_next_actions(out: &mut String, report: &DoctorReport) {
    out.push_str("\nNext actions\n");
    let actions = report.next_actions();
    if actions.is_empty() {
        out.push_str("No action needed.\n");
        return;
    }
    for (index, action) in actions.iter().enumerate() {
        let prefix = format!("{}. ", index + 1);
        push_wrapped_value(out, &prefix, action);
    }
}

fn push_findings(out: &mut String, report: &DoctorReport, verbose: bool) {
    out.push_str("\nFindings\n");
    let findings = report.finding_checks().collect::<Vec<_>>();
    if findings.is_empty() {
        out.push_str("No findings.\n");
        return;
    }
    for check in findings {
        push_finding(out, check, verbose);
    }
}

fn push_finding(out: &mut String, check: &DoctorCheck, verbose: bool) {
    let prefix = format!("{}  ", color_status(check.status));
    push_wrapped_value(out, &prefix, &check.message);
    if verbose {
        push_wrapped_value(out, "      Check: ", check.id);
        if let Some(rule) = check.rule.as_deref() {
            push_wrapped_value(out, "      Rule: ", rule);
        }
    }
    push_wrapped_value(out, "      Target: ", check.subject.as_str());
    if let Some(reason) = check.reason.as_deref() {
        push_wrapped_value(out, "      Reason: ", reason);
    }
    if let Some(next) = check.next_action.as_deref() {
        push_wrapped_value(out, "      Next: ", next);
    }
    out.push('\n');
}

fn push_healthy_areas(out: &mut String, report: &DoctorReport) {
    out.push_str("Healthy areas\n");
    let categories = report.healthy_categories();
    if categories.is_empty() {
        out.push_str("No healthy areas reported.\n");
        return;
    }
    for category in categories {
        push_wrapped_value(out, "OK  ", category.title());
    }
}

fn push_details(out: &mut String, report: &DoctorReport) {
    out.push_str("\nDetails\n");
    push_wrapped_value(out, "Workspace: ", report.workspace_display());
    out.push_str(&format!("Checks: {}\n", report.checks().len()));
}

fn push_wrapped_value(out: &mut String, prefix: &str, value: &str) {
    for line in layout::format_value_lines(prefix, value) {
        out.push_str(&line);
        out.push('\n');
    }
}

fn color_status(status: DoctorStatus) -> String {
    let label = status.as_str();
    match status {
        DoctorStatus::Ok => Style::new()
            .green()
            .for_stdout()
            .apply_to(label)
            .to_string(),
        DoctorStatus::Warn => Style::new()
            .yellow()
            .for_stdout()
            .apply_to(label)
            .to_string(),
        DoctorStatus::Fail => Style::new().red().for_stdout().apply_to(label).to_string(),
        DoctorStatus::Skip => Style::new().dim().for_stdout().apply_to(label).to_string(),
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_doctor_test.rs"]
mod tests;
