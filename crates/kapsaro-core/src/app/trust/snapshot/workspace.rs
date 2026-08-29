// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace member snapshots used by trust planning.
//! Verifies active recipient keys and keeps the reviewed active-member index.

use std::collections::BTreeMap;

use crate::feature::context::crypto::LocalKeyIdentity;
use crate::feature::context::expiry::collect_recipient_key_expiry_warnings_excluding_local_key;
use crate::feature::trust::judgment::build_active_members_by_kid;
use crate::io::workspace::members::load_active_member_files_at;
use crate::model::public_key::{PublicKey, VerifiedRecipientKey};
use crate::support::fs::relative::DirectoryFd;
use crate::Result;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct WorkspaceMemberSnapshot {
    active_members: Vec<PublicKey>,
    active_members_by_kid: BTreeMap<String, PublicKey>,
    member_handles: Vec<String>,
    verified_recipients: Vec<VerifiedRecipientKey>,
}

impl WorkspaceMemberSnapshot {
    /// Load the active members held under one workspace descriptor.
    ///
    /// A command that fixed its workspace reads the member set through that
    /// descriptor rather than through the configured path: resolving the path
    /// again would let a workspace repointed mid-command decide who counts as a
    /// member from another tree. Every reader here is such a command, so there
    /// is no path-addressed way in.
    pub(crate) fn load_at<D>(workspace: &D) -> Result<Self>
    where
        D: DirectoryFd,
    {
        Self::from_required_members(load_active_member_files_at(workspace)?)
    }

    /// A workspace with no active member authorizes nobody, so a write plan
    /// built on one would have no recipient to name.
    fn from_required_members(active_members: Vec<PublicKey>) -> Result<Self> {
        if active_members.is_empty() {
            return Err(crate::Error::build_not_found_error(
                "No active members found in workspace".to_string(),
            ));
        }
        Self::from_active_members(active_members)
    }

    pub fn from_active_members(active_members: Vec<PublicKey>) -> Result<Self> {
        debug!(
            "[TRUST] active member files loaded: count={}",
            active_members.len()
        );
        let mut member_handles = active_members
            .iter()
            .map(|member| member.protected.subject_handle.clone())
            .collect::<Vec<_>>();
        member_handles.sort();
        Self::build(active_members, member_handles)
    }

    fn build(active_members: Vec<PublicKey>, member_handles: Vec<String>) -> Result<Self> {
        let active_members_by_kid = build_active_members_by_kid(&active_members)?;
        let verified_recipients =
            crate::feature::verify::public_key::verify_recipient_public_keys(&active_members)?;

        Ok(Self {
            active_members,
            active_members_by_kid,
            member_handles,
            verified_recipients,
        })
    }

    pub fn active_members(&self) -> &[PublicKey] {
        &self.active_members
    }

    pub fn active_members_by_kid(&self) -> &BTreeMap<String, PublicKey> {
        &self.active_members_by_kid
    }

    pub fn matches_active_members(&self, other: &Self) -> bool {
        self.active_members_by_kid == other.active_members_by_kid
    }

    pub fn member_handles(&self) -> &[String] {
        &self.member_handles
    }

    pub fn verified_recipients(&self) -> &[VerifiedRecipientKey] {
        &self.verified_recipients
    }

    pub(crate) fn recipient_expiry_warnings_excluding_local_key(
        &self,
        local_key_identity: Option<&LocalKeyIdentity>,
    ) -> Result<Vec<String>> {
        collect_recipient_key_expiry_warnings_excluding_local_key(
            &self.verified_recipients,
            local_key_identity,
        )
    }
}
