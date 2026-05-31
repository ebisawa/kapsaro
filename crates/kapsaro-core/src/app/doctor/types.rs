// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DoctorStatus {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl DoctorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DoctorCategory {
    Workspace,
    MembersActive,
    MembersIncoming,
    LocalKeystore,
    LocalTrustStore,
    Artifacts,
    CiReadiness,
}

impl DoctorCategory {
    pub fn title(self) -> &'static str {
        match self {
            Self::Workspace => "Workspace structure",
            Self::MembersActive => "Active members",
            Self::MembersIncoming => "Incoming members",
            Self::LocalKeystore => "Local keystore",
            Self::LocalTrustStore => "Local trust store",
            Self::Artifacts => "Artifacts",
            Self::CiReadiness => "CI readiness",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorSubject {
    Path(String),
    Member(String),
    Artifact(String),
    Environment(String),
    General(String),
}

impl DoctorSubject {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Path(value)
            | Self::Member(value)
            | Self::Artifact(value)
            | Self::Environment(value)
            | Self::General(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    pub id: &'static str,
    pub category: DoctorCategory,
    pub status: DoctorStatus,
    pub subject: DoctorSubject,
    pub message: String,
    pub reason: Option<String>,
    pub next_action: Option<String>,
    pub rule: Option<String>,
}

impl DoctorCheck {
    pub fn new(
        id: &'static str,
        category: DoctorCategory,
        status: DoctorStatus,
        subject: DoctorSubject,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id,
            category,
            status,
            subject,
            message: message.into(),
            reason: None,
            next_action: None,
            rule: None,
        }
    }

    pub fn ok(
        id: &'static str,
        category: DoctorCategory,
        subject: DoctorSubject,
        message: impl Into<String>,
    ) -> Self {
        Self::new(id, category, DoctorStatus::Ok, subject, message)
    }

    pub fn warn(
        id: &'static str,
        category: DoctorCategory,
        subject: DoctorSubject,
        message: impl Into<String>,
    ) -> Self {
        Self::new(id, category, DoctorStatus::Warn, subject, message)
    }

    pub fn fail(
        id: &'static str,
        category: DoctorCategory,
        subject: DoctorSubject,
        message: impl Into<String>,
    ) -> Self {
        Self::new(id, category, DoctorStatus::Fail, subject, message)
    }

    pub fn skip(
        id: &'static str,
        category: DoctorCategory,
        subject: DoctorSubject,
        message: impl Into<String>,
    ) -> Self {
        Self::new(id, category, DoctorStatus::Skip, subject, message)
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn with_next_action(mut self, next_action: impl Into<String>) -> Self {
        self.next_action = Some(next_action.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct DoctorReport {
    workspace_display: String,
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    pub fn new(workspace_display: String) -> Self {
        Self {
            workspace_display,
            checks: Vec::new(),
        }
    }

    pub fn extend(&mut self, checks: impl IntoIterator<Item = DoctorCheck>) {
        self.checks.extend(checks);
    }

    pub fn checks(&self) -> &[DoctorCheck] {
        &self.checks
    }

    pub fn workspace_display(&self) -> &str {
        &self.workspace_display
    }

    pub fn overall_status(&self) -> DoctorStatus {
        if self
            .checks
            .iter()
            .any(|check| check.status == DoctorStatus::Fail)
        {
            DoctorStatus::Fail
        } else if self
            .checks
            .iter()
            .any(|check| check.status == DoctorStatus::Warn)
        {
            DoctorStatus::Warn
        } else if self
            .checks
            .iter()
            .all(|check| check.status == DoctorStatus::Skip)
        {
            DoctorStatus::Skip
        } else {
            DoctorStatus::Ok
        }
    }

    pub fn exit_code(&self) -> i32 {
        if self.overall_status() == DoctorStatus::Fail {
            1
        } else {
            0
        }
    }

    pub fn count(&self, status: DoctorStatus) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == status)
            .count()
    }

    pub fn finding_checks(&self) -> impl Iterator<Item = &DoctorCheck> {
        self.checks.iter().filter(|check| {
            matches!(
                check.status,
                DoctorStatus::Fail | DoctorStatus::Warn | DoctorStatus::Skip
            )
        })
    }

    pub fn healthy_categories(&self) -> Vec<DoctorCategory> {
        let mut categories = BTreeSet::new();
        for check in &self.checks {
            if check.status == DoctorStatus::Ok {
                categories.insert(check.category);
            }
        }
        categories.into_iter().collect()
    }

    pub fn next_actions(&self) -> Vec<&str> {
        let mut seen = BTreeSet::new();
        let mut actions = Vec::new();
        for status in [DoctorStatus::Fail, DoctorStatus::Warn] {
            for check in self.checks.iter().filter(|check| check.status == status) {
                let Some(action) = check.next_action.as_deref() else {
                    continue;
                };
                if seen.insert(action) {
                    actions.push(action);
                }
            }
        }
        actions
    }

    pub fn artifact_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| matches!(check.subject, DoctorSubject::Artifact(_)))
            .map(|check| check.subject.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn rewrap_recommended_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.next_action.as_deref() == Some("run kapsaro rewrap"))
            .map(|check| check.subject.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_doctor_types_test.rs"]
mod tests;
