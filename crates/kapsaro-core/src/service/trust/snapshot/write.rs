// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Write-path trust planning snapshots.
//! Enforces write policy and recipient trust using an immutable workspace snapshot.

use crate::feature::context::crypto::LocalKeyIdentity;
use crate::service::trust::evaluation::enforce_write_strict_key_checking;
use crate::service::trust::TrustPolicyEvaluator;
use crate::service::trust::{recipient_outcome_from_decision, RecipientTrustOutcome};
use crate::service::workspace::WorkspaceWriteCapabilities;
use crate::Result;

use super::context::{load_trust_context, TrustContext, WriteTrustOptions};
use super::workspace::WorkspaceMemberSnapshot;

#[derive(Debug, Clone)]
pub struct CommandTrustSnapshot {
    trust_ctx: TrustContext,
    evaluator: TrustPolicyEvaluator,
    workspace_members: WorkspaceMemberSnapshot,
}

impl CommandTrustSnapshot {
    /// Read the member set through the workspace descriptor this command fixed.
    ///
    /// The write and the trust decision have to be about one tree, so the
    /// members are read from the descriptor the execution bound to rather than
    /// from the configured path resolved a second time.
    pub(crate) fn load(
        capabilities: &WorkspaceWriteCapabilities<'_>,
        options: WriteTrustOptions,
    ) -> Result<Self> {
        let workspace_members = WorkspaceMemberSnapshot::load_at(capabilities.workspace())?;
        Self::from_workspace_members(capabilities, options, workspace_members)
    }

    pub(crate) fn from_workspace_members(
        capabilities: &WorkspaceWriteCapabilities<'_>,
        options: WriteTrustOptions,
        workspace_members: WorkspaceMemberSnapshot,
    ) -> Result<Self> {
        let loaded = load_trust_context(
            options,
            capabilities.trust(),
            workspace_members.active_members_by_kid().clone(),
        )?;
        enforce_write_strict_key_checking(loaded.trust_ctx.strict_key_checking)?;
        Ok(Self {
            trust_ctx: loaded.trust_ctx,
            evaluator: loaded.evaluator,
            workspace_members,
        })
    }

    pub fn trust_context(&self) -> &TrustContext {
        &self.trust_ctx
    }

    pub fn workspace_members(&self) -> &WorkspaceMemberSnapshot {
        &self.workspace_members
    }

    pub(crate) fn evaluator(&self) -> &TrustPolicyEvaluator {
        &self.evaluator
    }
}

pub struct WriteRecipientTrustPlan {
    trust_snapshot: CommandTrustSnapshot,
    recipient_trust: RecipientTrustOutcome,
    warnings: Vec<String>,
}

impl WriteRecipientTrustPlan {
    pub(crate) fn load(
        capabilities: &WorkspaceWriteCapabilities<'_>,
        options: WriteTrustOptions,
        local_key_identity: Option<&LocalKeyIdentity>,
    ) -> Result<Self> {
        let trust_snapshot = CommandTrustSnapshot::load(capabilities, options)?;
        let decision = trust_snapshot.evaluator().preflight_output_recipient_keys(
            trust_snapshot.workspace_members().active_members(),
            &trust_snapshot.trust_context().self_trust,
        )?;
        let recipient_trust = recipient_outcome_from_decision(
            decision,
            trust_snapshot.trust_context().review_available,
        )?;
        let warnings = trust_snapshot
            .workspace_members()
            .recipient_expiry_warnings_excluding_local_key(local_key_identity)?;
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
