// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::doctor::types::{
    DoctorCategory, DoctorCheck, DoctorReport, DoctorStatus, DoctorSubject,
};
use crate::cli::common::output::text::doctor::format_doctor_report;

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

    let summary = output.find("SecretEnv doctor").unwrap();
    let next = output.find("Next actions").unwrap();
    let findings = output.find("Findings").unwrap();
    let healthy = output.find("Healthy areas").unwrap();
    let details = output.find("Details").unwrap();
    assert!(summary < next);
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
