// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Immutable trust snapshots for a single command execution.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::enforcement::{enforce_recipients_trust, RecipientTrustOutcome};
use crate::app::trust::evaluation::enforce_policy_strict_key_checking;
use crate::app::trust::policy::{TrustPolicy, WriteTrustPolicy};
use crate::app::trust::store::load_optional_trust_store_for_member;
use crate::config::types::{
    StrictKeyChecking, StrictKeyCheckingResolution, StrictKeyCheckingSource,
};
use crate::feature::context::expiry::collect_recipient_key_expiry_warnings;
use crate::feature::trust::judgment::{
    build_active_members_by_kid, ActiveMemberSnapshot, SelfTrustSet,
};
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
};
use crate::io::workspace::members::load_active_member_files;
use crate::model::public_key::{PublicKey, VerifiedRecipientKey};
use crate::model::trust_store::{KnownKey, RecipientSetRecord};
use crate::support::tty;
use crate::Result;
use tracing::debug;

/// Immutable trust state snapshot for a single command execution.
#[derive(Debug, Clone)]
pub struct TrustContext {
    pub known_keys: Vec<KnownKey>,
    pub recipient_sets: Vec<RecipientSetRecord>,
    pub active_members_by_kid: BTreeMap<String, PublicKey>,
    pub self_trust: SelfTrustSet,
    pub strict_key_checking: StrictKeyCheckingResolution,
    pub is_interactive: bool,
    pub permission_warnings: Vec<String>,
}

impl TrustContext {
    pub fn active_member_snapshot(&self) -> ActiveMemberSnapshot<'_> {
        ActiveMemberSnapshot::new(&self.active_members_by_kid)
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceMemberSnapshot {
    active_members: Vec<PublicKey>,
    active_members_by_kid: BTreeMap<String, PublicKey>,
    member_handles: Vec<String>,
    verified_recipients: Vec<VerifiedRecipientKey>,
    recipient_expiry_warnings: Vec<String>,
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
        let recipient_expiry_warnings =
            collect_recipient_key_expiry_warnings(&verified_recipients)?;

        Ok(Self {
            active_members,
            active_members_by_kid,
            member_handles,
            verified_recipients,
            recipient_expiry_warnings,
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

    pub fn recipient_expiry_warnings(&self) -> &[String] {
        &self.recipient_expiry_warnings
    }
}

#[derive(Debug, Clone)]
pub struct CommandTrustSnapshot<P> {
    trust_ctx: TrustContext,
    workspace_members: WorkspaceMemberSnapshot,
    _policy: PhantomData<P>,
}

pub struct ReadTrustContextLoadResult {
    pub trust_ctx: TrustContext,
    pub warnings: Vec<String>,
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

pub fn load_read_trust_context(
    options: &CommonCommandOptions,
    workspace_path: &Path,
    self_member_handle: &str,
    self_sig_x: Option<[u8; 32]>,
    debug: bool,
) -> Result<ReadTrustContextLoadResult> {
    let verified_active_members = load_active_member_index_for_read_trust(workspace_path, debug)?;
    let trust_ctx = load_trust_context(
        options,
        verified_active_members.active_members_by_kid,
        self_member_handle,
        self_sig_x,
    )?;
    let mut warnings = trust_ctx.permission_warnings.clone();
    warnings.extend(verified_active_members.warnings);
    Ok(ReadTrustContextLoadResult {
        trust_ctx,
        warnings,
    })
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

fn load_trust_context(
    options: &CommonCommandOptions,
    active_members_by_kid: BTreeMap<String, PublicKey>,
    self_member_handle: &str,
    derive_self_sig_x: Option<[u8; 32]>,
) -> Result<TrustContext> {
    let strict_key_checking =
        crate::config::resolution::strict_key_checking::resolve_strict_key_checking();
    let is_interactive = tty::is_interactive();
    let (_, loaded) = load_optional_trust_store_for_member(options, self_member_handle)?;
    let (known_keys, recipient_sets, permission_warnings) = match loaded {
        Some(loaded) => (
            loaded.protected.known_keys,
            loaded.protected.recipient_sets,
            loaded.warnings,
        ),
        None => (Vec::new(), Vec::new(), Vec::new()),
    };
    let self_trust = load_self_trust(options, self_member_handle, derive_self_sig_x)?;

    if options.debug {
        debug!(
            "[TRUST] context: strict_key_checking={}, interactive={}, active_members={}, known_keys={}, recipient_sets={}",
            format_strict_key_checking(strict_key_checking),
            is_interactive,
            active_members_by_kid.len(),
            known_keys.len(),
            recipient_sets.len()
        );
    }

    Ok(TrustContext {
        known_keys,
        recipient_sets,
        active_members_by_kid,
        self_trust,
        strict_key_checking,
        is_interactive,
        permission_warnings,
    })
}

fn format_strict_key_checking(resolution: StrictKeyCheckingResolution) -> &'static str {
    match (resolution.mode, resolution.source) {
        (StrictKeyChecking::Yes, StrictKeyCheckingSource::Default) => "yes/default",
        (StrictKeyChecking::Yes, StrictKeyCheckingSource::ExplicitEnv) => "yes/env",
        (StrictKeyChecking::No, StrictKeyCheckingSource::ExplicitEnv) => "no/env",
        (StrictKeyChecking::No, StrictKeyCheckingSource::Default) => "no/default",
    }
}

struct VerifiedActiveMemberIndex {
    active_members_by_kid: BTreeMap<String, PublicKey>,
    warnings: Vec<String>,
}

fn load_active_member_index_for_read_trust(
    workspace_path: &Path,
    debug: bool,
) -> Result<VerifiedActiveMemberIndex> {
    let active_members = load_active_member_files(workspace_path)?;
    if active_members.is_empty() {
        return Err(crate::Error::build_not_found_error(
            "No active members found in workspace".to_string(),
        ));
    }

    let mut warnings = Vec::new();
    let mut verified_members = Vec::with_capacity(active_members.len());
    for member in active_members {
        let verified = verify_public_key_for_verification_context(
            &member,
            debug,
            WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
        )?;
        warnings.extend(verified.warnings);
        verified_members.push(verified.verified_public_key.document().clone());
    }
    let active_members_by_kid = build_active_members_by_kid(&verified_members)?;

    Ok(VerifiedActiveMemberIndex {
        active_members_by_kid,
        warnings,
    })
}

fn load_self_trust(
    options: &CommonCommandOptions,
    self_member_handle: &str,
    derive_self_sig_x: Option<[u8; 32]>,
) -> Result<SelfTrustSet> {
    let keystore_root = options.resolve_keystore_root()?;
    SelfTrustSet::try_new_with_keystore(self_member_handle, derive_self_sig_x, keystore_root)
}
