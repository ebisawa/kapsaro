// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust context loading for read and write planning.
//! Combines local trust-store records, active-member indexes, and self trust.

use std::collections::BTreeMap;
use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::load_optional_trust_store_for_member;
use crate::config::types::{
    StrictKeyChecking, StrictKeyCheckingResolution, StrictKeyCheckingSource,
};
use crate::feature::context::crypto::LocalKeyIdentity;
use crate::feature::trust::judgment::{
    build_active_members_by_kid, ActiveMemberSnapshot, SelfTrustSet,
};
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
};
use crate::io::workspace::members::load_active_member_files;
use crate::model::public_key::PublicKey;
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
    pub allow_non_member: bool,
    pub permission_warnings: Vec<String>,
}

impl TrustContext {
    pub fn active_member_snapshot(&self) -> ActiveMemberSnapshot<'_> {
        ActiveMemberSnapshot::new(&self.active_members_by_kid)
    }
}

pub struct ReadTrustContextLoadResult {
    pub trust_ctx: TrustContext,
    pub warnings: Vec<String>,
}

pub fn load_read_trust_context(
    options: &CommonCommandOptions,
    workspace_path: &Path,
    self_member_handle: &str,
    self_sig_x: Option<[u8; 32]>,
    local_key_identity: Option<&LocalKeyIdentity>,
    debug: bool,
) -> Result<ReadTrustContextLoadResult> {
    let verified_active_members =
        load_active_member_index_for_read_trust(workspace_path, local_key_identity, debug)?;
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

pub(super) fn load_trust_context(
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
            "[TRUST] context: strict_key_checking={}, interactive={}, allow_non_member={}, active_members={}, known_keys={}, recipient_sets={}",
            format_strict_key_checking(strict_key_checking),
            is_interactive,
            options.allow_non_member,
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
        allow_non_member: options.allow_non_member,
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
    local_key_identity: Option<&LocalKeyIdentity>,
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
        if !matches_local_key_identity(verified.verified_public_key.document(), local_key_identity)?
        {
            warnings.extend(verified.warnings);
        }
        verified_members.push(verified.verified_public_key.document().clone());
    }
    let active_members_by_kid = build_active_members_by_kid(&verified_members)?;

    Ok(VerifiedActiveMemberIndex {
        active_members_by_kid,
        warnings,
    })
}

fn matches_local_key_identity(
    public_key: &PublicKey,
    local_key_identity: Option<&LocalKeyIdentity>,
) -> Result<bool> {
    let Some(identity) = local_key_identity else {
        return Ok(false);
    };
    identity.matches_public_key(public_key)
}

fn load_self_trust(
    options: &CommonCommandOptions,
    self_member_handle: &str,
    derive_self_sig_x: Option<[u8; 32]>,
) -> Result<SelfTrustSet> {
    let keystore_root = options.resolve_keystore_root()?;
    SelfTrustSet::try_new_with_keystore(self_member_handle, derive_self_sig_x, keystore_root)
}
