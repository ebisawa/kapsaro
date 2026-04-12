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
use crate::config::resolution::strict_key_checking::resolve_strict_key_checking;
use crate::config::types::ResolvedStrictKeyChecking;
use crate::feature::context::expiry::collect_recipient_key_expiry_warnings;
use crate::feature::trust::judgment::{ActiveMemberSnapshot, SelfTrustSet};
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
};
use crate::io::workspace::members::load_active_member_files;
use crate::model::public_key::{PublicKey, VerifiedRecipientKey};
use crate::model::trust_store::KnownKey;
use crate::support::tty;
use crate::Result;

/// Immutable trust state snapshot for a single command execution.
#[derive(Debug, Clone)]
pub(crate) struct TrustContext {
    pub(crate) known_keys: Vec<KnownKey>,
    pub(crate) active_members_by_kid: BTreeMap<String, PublicKey>,
    pub(crate) self_trust: SelfTrustSet,
    pub(crate) strict_key_checking: ResolvedStrictKeyChecking,
    pub(crate) is_interactive: bool,
    pub(crate) permission_warnings: Vec<String>,
}

impl TrustContext {
    pub(crate) fn active_member_snapshot(&self) -> ActiveMemberSnapshot<'_> {
        ActiveMemberSnapshot::new(&self.active_members_by_kid)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WorkspaceMemberSnapshot {
    active_members: Vec<PublicKey>,
    active_members_by_kid: BTreeMap<String, PublicKey>,
    member_ids: Vec<String>,
    verified_recipients: Vec<VerifiedRecipientKey>,
    recipient_expiry_warnings: Vec<String>,
}

impl WorkspaceMemberSnapshot {
    pub(crate) fn load(workspace_path: &Path, debug: bool) -> Result<Self> {
        let active_members = load_active_member_files(workspace_path)?;
        if active_members.is_empty() {
            return Err(crate::Error::NotFound {
                message: "No active members found in workspace".to_string(),
            });
        }
        Self::from_active_members(active_members, debug)
    }

    pub(crate) fn from_active_members(active_members: Vec<PublicKey>, debug: bool) -> Result<Self> {
        let mut member_ids = active_members
            .iter()
            .map(|member| member.protected.member_id.clone())
            .collect::<Vec<_>>();
        member_ids.sort();
        Self::build(active_members, member_ids, debug)
    }

    fn build(active_members: Vec<PublicKey>, member_ids: Vec<String>, debug: bool) -> Result<Self> {
        let mut active_members_by_kid = BTreeMap::new();
        for member in &active_members {
            let kid = member.protected.kid.clone();
            if active_members_by_kid
                .insert(kid.clone(), member.clone())
                .is_some()
            {
                return Err(crate::Error::Config {
                    message: format!("Ambiguous key: kid '{}' found in multiple members", kid),
                });
            }
        }

        let recipient_expiry_warnings = collect_recipient_key_expiry_warnings(&active_members)?;
        let verified_recipients = crate::feature::verify::public_key::verify_recipient_public_keys(
            &active_members,
            debug,
        )?;

        Ok(Self {
            active_members,
            active_members_by_kid,
            member_ids,
            verified_recipients,
            recipient_expiry_warnings,
        })
    }

    pub(crate) fn active_members(&self) -> &[PublicKey] {
        &self.active_members
    }

    pub(crate) fn active_members_by_kid(&self) -> &BTreeMap<String, PublicKey> {
        &self.active_members_by_kid
    }

    pub(crate) fn matches_active_members(&self, other: &Self) -> bool {
        self.active_members_by_kid == other.active_members_by_kid
    }

    pub(crate) fn member_ids(&self) -> &[String] {
        &self.member_ids
    }

    pub(crate) fn verified_recipients(&self) -> &[VerifiedRecipientKey] {
        &self.verified_recipients
    }

    pub(crate) fn recipient_expiry_warnings(&self) -> &[String] {
        &self.recipient_expiry_warnings
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CommandTrustSnapshot<P> {
    trust_ctx: TrustContext,
    workspace_members: WorkspaceMemberSnapshot,
    _policy: PhantomData<P>,
}

pub(crate) struct ReadTrustContextLoad {
    pub(crate) trust_ctx: TrustContext,
    pub(crate) warnings: Vec<String>,
}

impl<P> CommandTrustSnapshot<P>
where
    P: TrustPolicy,
{
    pub(crate) fn load(
        options: &CommonCommandOptions,
        workspace_path: &Path,
        self_member_id: &str,
        self_sig_x: Option<[u8; 32]>,
        debug: bool,
    ) -> Result<Self> {
        let workspace_members = WorkspaceMemberSnapshot::load(workspace_path, debug)?;
        Self::from_workspace_members(options, workspace_members, self_member_id, self_sig_x)
    }

    pub(crate) fn from_workspace_members(
        options: &CommonCommandOptions,
        workspace_members: WorkspaceMemberSnapshot,
        self_member_id: &str,
        self_sig_x: Option<[u8; 32]>,
    ) -> Result<Self> {
        let trust_ctx = load_trust_context(
            options,
            workspace_members.active_members_by_kid().clone(),
            self_member_id,
            self_sig_x,
        )?;
        enforce_policy_strict_key_checking::<P>(trust_ctx.strict_key_checking)?;
        Ok(Self {
            trust_ctx,
            workspace_members,
            _policy: PhantomData,
        })
    }

    pub(crate) fn trust_context(&self) -> &TrustContext {
        &self.trust_ctx
    }

    pub(crate) fn workspace_members(&self) -> &WorkspaceMemberSnapshot {
        &self.workspace_members
    }
}

pub(crate) fn load_read_trust_context(
    options: &CommonCommandOptions,
    workspace_path: &Path,
    self_member_id: &str,
    self_sig_x: Option<[u8; 32]>,
    debug: bool,
) -> Result<ReadTrustContextLoad> {
    let verified_active_members = load_active_member_index_for_read_trust(workspace_path, debug)?;
    let trust_ctx = load_trust_context(
        options,
        verified_active_members.active_members_by_kid,
        self_member_id,
        self_sig_x,
    )?;
    let mut warnings = trust_ctx.permission_warnings.clone();
    warnings.extend(verified_active_members.warnings);
    Ok(ReadTrustContextLoad {
        trust_ctx,
        warnings,
    })
}

pub(crate) struct WriteRecipientTrustPlan<P> {
    trust_snapshot: CommandTrustSnapshot<P>,
    recipient_trust: RecipientTrustOutcome,
    warnings: Vec<String>,
}

impl<P> WriteRecipientTrustPlan<P>
where
    P: WriteTrustPolicy,
{
    pub(crate) fn load(
        options: &CommonCommandOptions,
        workspace_path: &Path,
        self_member_id: &str,
        self_sig_x: Option<[u8; 32]>,
        debug: bool,
    ) -> Result<Self> {
        let trust_snapshot = CommandTrustSnapshot::<P>::load(
            options,
            workspace_path,
            self_member_id,
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

    pub(crate) fn trust_context(&self) -> &TrustContext {
        self.trust_snapshot.trust_context()
    }

    pub(crate) fn workspace_members(&self) -> &WorkspaceMemberSnapshot {
        self.trust_snapshot.workspace_members()
    }

    pub(crate) fn recipient_trust(&self) -> &RecipientTrustOutcome {
        &self.recipient_trust
    }

    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

fn load_trust_context(
    options: &CommonCommandOptions,
    active_members_by_kid: BTreeMap<String, PublicKey>,
    self_member_id: &str,
    current_self_sig_x: Option<[u8; 32]>,
) -> Result<TrustContext> {
    let strict_key_checking = resolve_strict_key_checking();
    let is_interactive = tty::is_interactive();
    let (_, loaded) = load_optional_trust_store_for_member(options, self_member_id)?;
    let (known_keys, permission_warnings) = match loaded {
        Some(loaded) => (loaded.protected.known_keys, loaded.warnings),
        None => (Vec::new(), Vec::new()),
    };
    let self_trust = load_self_trust(options, self_member_id, current_self_sig_x)?;

    Ok(TrustContext {
        known_keys,
        active_members_by_kid,
        self_trust,
        strict_key_checking,
        is_interactive,
        permission_warnings,
    })
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
        return Err(crate::Error::NotFound {
            message: "No active members found in workspace".to_string(),
        });
    }

    let mut active_members_by_kid = BTreeMap::new();
    let mut warnings = Vec::new();
    for member in active_members {
        let verified = verify_public_key_for_verification_context(
            &member,
            debug,
            WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
        )?;
        warnings.extend(verified.warnings);
        let verified_member = verified.verified_public_key.document().clone();
        let kid = verified_member.protected.kid.clone();
        if active_members_by_kid
            .insert(kid.clone(), verified_member)
            .is_some()
        {
            return Err(crate::Error::Config {
                message: format!("Ambiguous key: kid '{}' found in multiple members", kid),
            });
        }
    }

    Ok(VerifiedActiveMemberIndex {
        active_members_by_kid,
        warnings,
    })
}

fn load_self_trust(
    options: &CommonCommandOptions,
    self_member_id: &str,
    current_self_sig_x: Option<[u8; 32]>,
) -> Result<SelfTrustSet> {
    let keystore_root = options.resolve_keystore_root()?;
    SelfTrustSet::try_new_with_keystore(self_member_id, current_self_sig_x, keystore_root)
}
