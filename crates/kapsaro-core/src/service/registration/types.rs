// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Types describing one member registration from plan to outcome.
//! Carries validated member and key identity rather than raw strings.

use std::path::PathBuf;

use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::ssh::SshDeterminismStatus;
use crate::service::key::generate::KeyGenerationHome;

pub use crate::service::online::OnlineVerificationStatus;

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

#[derive(Debug, Clone)]
pub struct RegistrationKeyPlan {
    resolution: RegistrationKeyPlanResolution,
}

#[derive(Debug, Clone)]
pub(crate) enum RegistrationKeyPlanResolution {
    UseExisting {
        kid: Kid,
        expires_at: String,
        keystore: KeystoreAccess,
    },
    GenerateNew {
        home: KeyGenerationHome,
    },
}

impl RegistrationKeyPlan {
    pub(crate) fn use_existing(kid: Kid, expires_at: String, keystore: KeystoreAccess) -> Self {
        Self {
            resolution: RegistrationKeyPlanResolution::UseExisting {
                kid,
                expires_at,
                keystore,
            },
        }
    }

    pub(crate) fn generate_new(home: KeyGenerationHome) -> Self {
        Self {
            resolution: RegistrationKeyPlanResolution::GenerateNew { home },
        }
    }

    pub fn needs_new_key(&self) -> bool {
        matches!(
            self.resolution,
            RegistrationKeyPlanResolution::GenerateNew { .. }
        )
    }

    /// Read the kid a plan resolved to reuse.
    ///
    /// Production consumes the plan through `into_resolution`, so this
    /// accessor exists for the tests that assert which kid was chosen.
    #[cfg(test)]
    pub(crate) fn existing_kid(&self) -> Option<&Kid> {
        match &self.resolution {
            RegistrationKeyPlanResolution::UseExisting { kid, .. } => Some(kid),
            RegistrationKeyPlanResolution::GenerateNew { .. } => None,
        }
    }

    pub(crate) fn into_resolution(self) -> RegistrationKeyPlanResolution {
        self.resolution
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

impl From<RegistrationTarget> for crate::io::workspace::members::MemberStatus {
    fn from(value: RegistrationTarget) -> Self {
        match value {
            RegistrationTarget::Active => Self::Active,
            RegistrationTarget::Incoming => Self::Incoming,
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
    pub member_handle: MemberHandle,
    pub key_result: MemberKeySetupResult,
}

impl MemberSetupResult {
    pub fn kid(&self) -> &Kid {
        &self.key_result.kid
    }
}

#[derive(Debug, Clone)]
pub struct MemberKeySetupResult {
    pub kid: Kid,
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
    pub setup: MemberSetupResult,
    pub target: RegistrationTarget,
    pub is_new_workspace: bool,
    pub conflict_exists: bool,
    pub active_membership: ActiveMembershipState,
    pub(crate) keystore: KeystoreAccess,
}

#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    pub mode: RegistrationMode,
    pub workspace_path: PathBuf,
    pub target: RegistrationTarget,
    pub is_new_workspace: bool,
    pub member_handle: MemberHandle,
    pub key_result: MemberKeySetupResult,
    pub result: RegistrationResult,
}
