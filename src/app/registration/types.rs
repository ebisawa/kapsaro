// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::app::verification::OnlineVerificationStatus;
use crate::model::ssh::SshDeterminismStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationResult {
    NewMember,
    Updated,
    AlreadyExists,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    Init,
    Join,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationKeyPlan {
    UseExisting { kid: String, expires_at: String },
    GenerateNew,
}

impl RegistrationKeyPlan {
    pub fn needs_new_key(&self) -> bool {
        matches!(self, Self::GenerateNew)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationTarget {
    Active,
    Incoming,
}

impl RegistrationTarget {
    pub fn directory_name(self) -> &'static str {
        match self {
            Self::Active => "members/active",
            Self::Incoming => "members/incoming",
        }
    }
}

impl From<crate::io::workspace::members::MemberStatus> for RegistrationTarget {
    fn from(value: crate::io::workspace::members::MemberStatus) -> Self {
        match value {
            crate::io::workspace::members::MemberStatus::Active => Self::Active,
            crate::io::workspace::members::MemberStatus::Incoming => Self::Incoming,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveMembershipState {
    None,
    SameKey,
    DifferentKey,
}

#[derive(Debug, Clone)]
pub struct MemberSetupResult {
    pub member_handle: String,
    pub key_result: MemberKeySetupResult,
}

impl MemberSetupResult {
    pub fn kid(&self) -> &str {
        &self.key_result.kid
    }
}

#[derive(Debug, Clone)]
pub struct MemberKeySetupResult {
    pub kid: String,
    pub created: bool,
    pub expires_at: String,
    pub ssh_fingerprint: Option<String>,
    pub ssh_determinism: Option<SshDeterminismStatus>,
    pub github_verification: OnlineVerificationStatus,
}

#[derive(Debug, Clone)]
pub struct RegistrationCommand {
    pub mode: RegistrationMode,
    pub workspace_path: PathBuf,
    pub keystore_root: PathBuf,
    pub setup: MemberSetupResult,
    pub target: RegistrationTarget,
    pub is_new_workspace: bool,
    pub conflict_exists: bool,
    pub active_membership: ActiveMembershipState,
}

#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    pub mode: RegistrationMode,
    pub workspace_path: PathBuf,
    pub target: RegistrationTarget,
    pub is_new_workspace: bool,
    pub member_handle: String,
    pub key_result: MemberKeySetupResult,
    pub result: RegistrationResult,
}
