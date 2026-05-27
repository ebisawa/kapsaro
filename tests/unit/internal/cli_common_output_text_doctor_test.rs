// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli::common::output::text::doctor::format_doctor_report;
use secretenv_core::cli_api::app::doctor::types::{
    DoctorCategory, DoctorCheck, DoctorReport, DoctorStatus, DoctorSubject,
};

#[test]
fn test_doctor_text_output_orders_sections() {
    let mut report = DoctorReport::new("workspace".to_string());
    report.extend([DoctorCheck::new(
        "workspace.resolve",
        DoctorCategory::Workspace,
        DoctorStatus::Ok,
        DoctorSubject::Path(".secretenv".into()),
        "Workspace resolved",
    )]);
    report.extend([DoctorCheck::new(
        "trust_store.present",
        DoctorCategory::LocalTrustStore,
        DoctorStatus::Warn,
        DoctorSubject::Path("trust/alice@example.com.json".into()),
        "Local trust store is missing",
    )
    .with_reason("approval cache is not available")
    .with_next_action("run secretenv member verify --approve")]);

    let output = format_doctor_report(&report, false);

    let next = output.find("Next actions").unwrap();
    let findings = output.find("Findings").unwrap();
    let healthy = output.find("Healthy areas").unwrap();
    let details = output.find("Details").unwrap();
    assert!(next < findings);
    assert!(findings < healthy);
    assert!(healthy < details);
    assert!(output.contains("Status: WARN"));
    assert!(output.contains("run secretenv member verify --approve"));
}

#[test]
fn test_doctor_report_exit_code_fails_only_on_fail() {
    let mut report = DoctorReport::new("workspace".to_string());
    report.extend([DoctorCheck::new(
        "members.incoming.pending",
        DoctorCategory::MembersIncoming,
        DoctorStatus::Warn,
        DoctorSubject::Path("members/incoming/bob@example.com.json".into()),
        "Incoming member is pending",
    )]);
    assert_eq!(report.exit_code(), 0);

    report.extend([DoctorCheck::new(
        "artifact.signature",
        DoctorCategory::Artifacts,
        DoctorStatus::Fail,
        DoctorSubject::Path("secrets/default.kvenc".into()),
        "Artifact signature verification failed",
    )]);
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn test_doctor_text_output_keeps_long_messages_and_paths_inline() {
    let workspace = format!("/workspace/{}", "nested-directory/".repeat(8));
    let subject = format!("secrets/{}.kvenc", "long-path-segment".repeat(10));
    let message = format!(
        "Artifact recipient handle {} does not match an active workspace member",
        "alice.release.engineering.".repeat(5)
    );
    let reason = format!(
        "recipient hash {} could not be matched to current members",
        "abcdef0123456789".repeat(8)
    );
    let next_action = format!("run secretenv rewrap --target {subject}");
    let mut report = DoctorReport::new(workspace);
    report.extend([DoctorCheck::new(
        "artifact.recipient_handle",
        DoctorCategory::Artifacts,
        DoctorStatus::Fail,
        DoctorSubject::Path(subject),
        message,
    )
    .with_reason(reason)
    .with_next_action(next_action)]);

    let output = format_doctor_report(&report, true);

    assert!(output.contains("/workspace/nested-directory/"));
    assert!(output.contains("alice.release.engineering."));
    assert!(output.contains("abcdef0123456789"));
    assert!(output.contains("run secretenv rewrap --target secrets/"));
}
