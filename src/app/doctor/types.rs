// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DoctorStatus {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl DoctorStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DoctorCategory {
    Workspace,
    MembersActive,
    MembersIncoming,
    LocalKeystore,
    LocalTrustStore,
    Artifacts,
    CiReadiness,
}

impl DoctorCategory {
    pub(crate) fn title(self) -> &'static str {
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
pub(crate) enum DoctorSubject {
    Path(String),
    Member(String),
    Artifact(String),
    Environment(String),
    General(String),
}

impl DoctorSubject {
    pub(crate) fn as_str(&self) -> &str {
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
pub(crate) struct DoctorCheck {
    pub(crate) id: &'static str,
    pub(crate) category: DoctorCategory,
    pub(crate) status: DoctorStatus,
    pub(crate) subject: DoctorSubject,
    pub(crate) message: String,
    pub(crate) reason: Option<String>,
    pub(crate) next_action: Option<String>,
    pub(crate) rule: Option<String>,
}

impl DoctorCheck {
    pub(crate) fn new(
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

    pub(crate) fn ok(
        id: &'static str,
        category: DoctorCategory,
        subject: DoctorSubject,
        message: impl Into<String>,
    ) -> Self {
        Self::new(id, category, DoctorStatus::Ok, subject, message)
    }

    pub(crate) fn warn(
        id: &'static str,
        category: DoctorCategory,
        subject: DoctorSubject,
        message: impl Into<String>,
    ) -> Self {
        Self::new(id, category, DoctorStatus::Warn, subject, message)
    }

    pub(crate) fn fail(
        id: &'static str,
        category: DoctorCategory,
        subject: DoctorSubject,
        message: impl Into<String>,
    ) -> Self {
        Self::new(id, category, DoctorStatus::Fail, subject, message)
    }

    pub(crate) fn skip(
        id: &'static str,
        category: DoctorCategory,
        subject: DoctorSubject,
        message: impl Into<String>,
    ) -> Self {
        Self::new(id, category, DoctorStatus::Skip, subject, message)
    }

    pub(crate) fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub(crate) fn with_next_action(mut self, next_action: impl Into<String>) -> Self {
        self.next_action = Some(next_action.into());
        self
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DoctorReport {
    workspace_display: String,
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    pub(crate) fn new(workspace_display: String) -> Self {
        Self {
            workspace_display,
            checks: Vec::new(),
        }
    }

    pub(crate) fn extend(&mut self, checks: impl IntoIterator<Item = DoctorCheck>) {
        self.checks.extend(checks);
    }

    pub(crate) fn checks(&self) -> &[DoctorCheck] {
        &self.checks
    }

    pub(crate) fn workspace_display(&self) -> &str {
        &self.workspace_display
    }

    pub(crate) fn overall_status(&self) -> DoctorStatus {
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

    pub(crate) fn exit_code(&self) -> i32 {
        if self.overall_status() == DoctorStatus::Fail {
            1
        } else {
            0
        }
    }

    pub(crate) fn count(&self, status: DoctorStatus) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == status)
            .count()
    }

    pub(crate) fn finding_checks(&self) -> impl Iterator<Item = &DoctorCheck> {
        self.checks.iter().filter(|check| {
            matches!(
                check.status,
                DoctorStatus::Fail | DoctorStatus::Warn | DoctorStatus::Skip
            )
        })
    }

    pub(crate) fn healthy_categories(&self) -> Vec<DoctorCategory> {
        let mut categories = BTreeSet::new();
        for check in &self.checks {
            if check.status == DoctorStatus::Ok {
                categories.insert(check.category);
            }
        }
        categories.into_iter().collect()
    }

    pub(crate) fn next_actions(&self) -> Vec<&str> {
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

    pub(crate) fn artifact_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| matches!(check.subject, DoctorSubject::Artifact(_)))
            .map(|check| check.subject.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub(crate) fn rewrap_recommended_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.next_action.as_deref() == Some("run secretenv rewrap"))
            .map(|check| check.subject.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_doctor_types_test.rs"]
mod tests;
