// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Write-path trust planning snapshots.
//! Enforces write policy and recipient trust using an immutable workspace snapshot.

use std::marker::PhantomData;
use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::enforcement::enforce_recipients_trust;
use crate::app::trust::evaluation::enforce_policy_strict_key_checking;
use crate::app::trust::policy::{TrustPolicy, WriteTrustPolicy};
use crate::app::trust::RecipientTrustOutcome;
use crate::Result;

use super::context::{load_trust_context, TrustContext};
use super::workspace::WorkspaceMemberSnapshot;

#[derive(Debug, Clone)]
pub struct CommandTrustSnapshot<P> {
    trust_ctx: TrustContext,
    workspace_members: WorkspaceMemberSnapshot,
    _policy: PhantomData<P>,
}

impl<P> CommandTrustSnapshot<P>
where
    P: TrustPolicy,
{
    pub fn load(
        options: &CommonCommandOptions,
        workspace_path: &Path,
        self_member_handle: &str,
        self_sig_x: Option<[u8; 32]>,
        debug: bool,
    ) -> Result<Self> {
        let workspace_members = WorkspaceMemberSnapshot::load(workspace_path, debug)?;
        Self::from_workspace_members(options, workspace_members, self_member_handle, self_sig_x)
    }

    pub fn from_workspace_members(
        options: &CommonCommandOptions,
        workspace_members: WorkspaceMemberSnapshot,
        self_member_handle: &str,
        self_sig_x: Option<[u8; 32]>,
    ) -> Result<Self> {
        let trust_ctx = load_trust_context(
            options,
            workspace_members.active_members_by_kid().clone(),
            self_member_handle,
            self_sig_x,
        )?;
        enforce_policy_strict_key_checking::<P>(trust_ctx.strict_key_checking)?;
        Ok(Self {
            trust_ctx,
            workspace_members,
            _policy: PhantomData,
        })
    }

    pub fn trust_context(&self) -> &TrustContext {
        &self.trust_ctx
    }

    pub fn workspace_members(&self) -> &WorkspaceMemberSnapshot {
        &self.workspace_members
    }
}

pub struct WriteRecipientTrustPlan<P> {
    trust_snapshot: CommandTrustSnapshot<P>,
    recipient_trust: RecipientTrustOutcome,
    warnings: Vec<String>,
}

impl<P> WriteRecipientTrustPlan<P>
where
    P: WriteTrustPolicy,
{
    pub fn load(
        options: &CommonCommandOptions,
        workspace_path: &Path,
        self_member_handle: &str,
        self_sig_x: Option<[u8; 32]>,
        debug: bool,
    ) -> Result<Self> {
        let trust_snapshot = CommandTrustSnapshot::<P>::load(
            options,
            workspace_path,
            self_member_handle,
            self_sig_x,
            debug,
        )?;
        let recipient_trust = enforce_recipients_trust(
            trust_snapshot.trust_context(),
            trust_snapshot.workspace_members().active_members(),
        )?;
        let mut warnings = trust_snapshot.trust_context().permission_warnings.clone();
        warnings.extend(
            trust_snapshot
                .workspace_members()
                .recipient_expiry_warnings()
                .iter()
                .cloned(),
        );
        Ok(Self {
            trust_snapshot,
            recipient_trust,
            warnings,
        })
    }

    pub fn trust_context(&self) -> &TrustContext {
        self.trust_snapshot.trust_context()
    }

    pub fn workspace_members(&self) -> &WorkspaceMemberSnapshot {
        self.trust_snapshot.workspace_members()
    }

    pub fn recipient_trust(&self) -> &RecipientTrustOutcome {
        &self.recipient_trust
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}
