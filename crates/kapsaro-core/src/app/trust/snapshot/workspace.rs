// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace member snapshots used by trust planning.
//! Verifies active recipient keys and keeps the reviewed active-member index.

use std::collections::BTreeMap;
use std::path::Path;

use crate::feature::context::crypto::LocalKeyIdentity;
use crate::feature::context::expiry::collect_recipient_key_expiry_warnings_excluding_local_key;
use crate::feature::trust::judgment::build_active_members_by_kid;
use crate::io::workspace::members::load_active_member_files;
use crate::model::public_key::{PublicKey, VerifiedRecipientKey};
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
    pub fn load(workspace_path: &Path, debug: bool) -> Result<Self> {
        let active_members = load_active_member_files(workspace_path)?;
        if active_members.is_empty() {
            return Err(crate::Error::build_not_found_error(
                "No active members found in workspace".to_string(),
            ));
        }
        Self::from_active_members(active_members, debug)
    }

    pub fn from_active_members(active_members: Vec<PublicKey>, debug: bool) -> Result<Self> {
        if debug {
            debug!(
                "[TRUST] active member files loaded: count={}",
                active_members.len()
            );
        }
        let mut member_handles = active_members
            .iter()
            .map(|member| member.protected.subject_handle.clone())
            .collect::<Vec<_>>();
        member_handles.sort();
        Self::build(active_members, member_handles, debug)
    }

    fn build(
        active_members: Vec<PublicKey>,
        member_handles: Vec<String>,
        debug: bool,
    ) -> Result<Self> {
        let active_members_by_kid = build_active_members_by_kid(&active_members)?;
        let verified_recipients = crate::feature::verify::public_key::verify_recipient_public_keys(
            &active_members,
            debug,
        )?;

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
