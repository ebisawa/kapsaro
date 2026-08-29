// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Write-path trust planning snapshots.
//! Enforces write policy and recipient trust using an immutable workspace snapshot.

use std::marker::PhantomData;

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::enforcement::enforce_recipients_trust;
use crate::app::trust::evaluation::enforce_policy_strict_key_checking;
use crate::app::trust::policy::{TrustPolicy, WriteTrustPolicy};
use crate::app::trust::RecipientTrustOutcome;
use crate::feature::context::crypto::LocalKeyIdentity;
use crate::io::keystore::access::KeystoreAccess;
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
    /// Read the member set through the workspace descriptor this command fixed.
    ///
    /// The write and the trust decision have to be about one tree, so the
    /// members are read from the descriptor the execution bound to rather than
    /// from the configured path resolved a second time.
    pub fn load(
        options: &CommonCommandOptions,
        execution: &ExecutionContext,
        keystore: &KeystoreAccess,
    ) -> Result<Self> {
        let workspace_members =
            WorkspaceMemberSnapshot::load_at(execution.fixed_workspace_directory()?)?;
        Self::from_workspace_members(options, execution, workspace_members, keystore)
    }

    pub fn from_workspace_members(
        options: &CommonCommandOptions,
        execution: &ExecutionContext,
        workspace_members: WorkspaceMemberSnapshot,
        keystore: &KeystoreAccess,
    ) -> Result<Self> {
        let trust_ctx = load_trust_context(
            options,
            execution,
            workspace_members.active_members_by_kid().clone(),
            keystore,
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
        execution: &ExecutionContext,
        local_key_identity: Option<&LocalKeyIdentity>,
        keystore: &KeystoreAccess,
    ) -> Result<Self> {
        let trust_snapshot = CommandTrustSnapshot::<P>::load(options, execution, keystore)?;
        let recipient_trust = enforce_recipients_trust(
            trust_snapshot.trust_context(),
            trust_snapshot.workspace_members().active_members(),
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
