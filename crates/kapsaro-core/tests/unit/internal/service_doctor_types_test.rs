// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{DoctorCategory, DoctorCheck, DoctorReport, DoctorStatus, DoctorSubject};

fn check(
    status: DoctorStatus,
    category: DoctorCategory,
    subject: DoctorSubject,
    next_action: Option<&str>,
) -> DoctorCheck {
    let mut check = DoctorCheck::new("test.check", category, status, subject, "message");
    if let Some(next_action) = next_action {
        check = check.with_next_action(next_action);
    }
    check
}

#[test]
fn test_doctor_report_overall_status_prefers_fail() {
    let mut report = DoctorReport::new("workspace".to_string());
    report.extend([
        check(
            DoctorStatus::Warn,
            DoctorCategory::Workspace,
            DoctorSubject::General("warn".to_string()),
            None,
        ),
        check(
            DoctorStatus::Fail,
            DoctorCategory::Artifacts,
            DoctorSubject::General("fail".to_string()),
            None,
        ),
    ]);

    assert_eq!(report.overall_status(), DoctorStatus::Fail);
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn test_doctor_report_overall_status_all_skip() {
    let mut report = DoctorReport::new("workspace".to_string());
    report.extend([check(
        DoctorStatus::Skip,
        DoctorCategory::CiReadiness,
        DoctorSubject::Environment("KAPSARO_PRIVATE_KEY".to_string()),
        None,
    )]);

    assert_eq!(report.overall_status(), DoctorStatus::Skip);
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn test_doctor_report_next_actions_dedupes_fail_before_warn() {
    let mut report = DoctorReport::new("workspace".to_string());
    report.extend([
        check(
            DoctorStatus::Warn,
            DoctorCategory::LocalTrustStore,
            DoctorSubject::General("warn".to_string()),
            Some("run kapsaro member verify --approve"),
        ),
        check(
            DoctorStatus::Fail,
            DoctorCategory::Artifacts,
            DoctorSubject::Artifact("secrets/app.env.encrypted".to_string()),
            Some("run kapsaro rewrap"),
        ),
        check(
            DoctorStatus::Warn,
            DoctorCategory::Artifacts,
            DoctorSubject::Artifact("secrets/other.env.encrypted".to_string()),
            Some("run kapsaro rewrap"),
        ),
    ]);

    assert_eq!(
        report.next_actions(),
        vec!["run kapsaro rewrap", "run kapsaro member verify --approve"]
    );
}

#[test]
fn test_doctor_report_counts_unique_artifacts() {
    let mut report = DoctorReport::new("workspace".to_string());
    report.extend([
        check(
            DoctorStatus::Fail,
            DoctorCategory::Artifacts,
            DoctorSubject::Artifact("secrets/app.env.encrypted".to_string()),
            Some("run kapsaro rewrap"),
        ),
        check(
            DoctorStatus::Warn,
            DoctorCategory::Artifacts,
            DoctorSubject::Artifact("secrets/app.env.encrypted".to_string()),
            Some("run kapsaro rewrap"),
        ),
        check(
            DoctorStatus::Warn,
            DoctorCategory::Artifacts,
            DoctorSubject::Artifact("secrets/other.env.encrypted".to_string()),
            Some("review disclosure history and rotate secret values if needed"),
        ),
    ]);

    assert_eq!(report.artifact_count(), 2);
    assert_eq!(report.rewrap_recommended_count(), 1);
}

#[test]
fn test_doctor_report_healthy_categories_are_sorted_and_unique() {
    let mut report = DoctorReport::new("workspace".to_string());
    report.extend([
        check(
            DoctorStatus::Ok,
            DoctorCategory::Artifacts,
            DoctorSubject::General("artifact".to_string()),
            None,
        ),
        check(
            DoctorStatus::Ok,
            DoctorCategory::Workspace,
            DoctorSubject::General("workspace".to_string()),
            None,
        ),
        check(
            DoctorStatus::Ok,
            DoctorCategory::Artifacts,
            DoctorSubject::General("artifact again".to_string()),
            None,
        ),
    ]);

    assert_eq!(
        report.healthy_categories(),
        vec![DoctorCategory::Workspace, DoctorCategory::Artifacts]
    );
}
