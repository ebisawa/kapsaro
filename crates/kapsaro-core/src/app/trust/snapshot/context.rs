// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust context loading for read and write planning.
//! Combines local trust-store records, active-member indexes, and self trust.

use std::collections::BTreeMap;

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::build_workspace_not_found_error;
use crate::app::trust::store::load_execution_trust_store;
use crate::config::types::{
    StrictKeyChecking, StrictKeyCheckingResolution, StrictKeyCheckingSource,
};
use crate::feature::context::crypto::LocalKeyIdentity;
use crate::feature::trust::judgment::{
    build_active_members_by_kid, ActiveMemberSnapshot, SelfTrustSet,
};
use crate::feature::trust::store_mutation::TrustStoreState;
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
};
use crate::io::keystore::access::KeystoreAccess;
use crate::io::workspace::members::load_active_member_files_at;
use crate::model::public_key::PublicKey;
use crate::model::trust_store::{KnownKey, RecipientSetRecord};
use crate::support::fs::relative::DirectoryFd;
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

/// Load the read-side trust context from the identities `execution` fixed.
/// `subject` names the command in the error raised without a workspace.
pub fn load_read_trust_context(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    subject: &str,
) -> Result<ReadTrustContextLoadResult> {
    let workspace = execution
        .fixed_workspace_directory()
        .map_err(|_| build_workspace_not_found_error(subject))?;
    let key_ctx = execution.key_ctx.inner();
    let verified_active_members =
        load_active_member_index_for_read_trust(workspace, Some(key_ctx.local_key_identity()))?;
    let loaded = load_execution_trust_store(execution)?;
    let trust_ctx = build_trust_context(
        options,
        verified_active_members.active_members_by_kid,
        &execution.member_handle,
        Some(key_ctx.self_signature_public_key_x()),
        loaded,
        key_ctx.local_keystore_access(),
    )?;
    let warnings = verified_active_members.warnings;
    Ok(ReadTrustContextLoadResult {
        trust_ctx,
        warnings,
    })
}

pub(super) fn load_trust_context(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    active_members_by_kid: BTreeMap<String, PublicKey>,
    keystore: &KeystoreAccess,
) -> Result<TrustContext> {
    let loaded = load_execution_trust_store(execution)?;
    build_trust_context(
        options,
        active_members_by_kid,
        &execution.member_handle,
        Some(execution.key_ctx.inner().self_signature_public_key_x()),
        loaded,
        Some(keystore),
    )
}

fn log_trust_context(
    strict_key_checking: StrictKeyCheckingResolution,
    is_interactive: bool,
    allow_non_member: bool,
    active_members: usize,
    known_keys: usize,
    recipient_sets: usize,
) {
    debug!(
        "[TRUST] context: strict_key_checking={}, interactive={}, allow_non_member={}, active_members={}, known_keys={}, recipient_sets={}",
        format_strict_key_checking(strict_key_checking),
        is_interactive,
        allow_non_member,
        active_members,
        known_keys,
        recipient_sets
    );
}

fn build_trust_context(
    options: &CommonCommandOptions,
    active_members_by_kid: BTreeMap<String, PublicKey>,
    self_member_handle: &str,
    derive_self_sig_x: Option<[u8; 32]>,
    loaded: Option<TrustStoreState>,
    keystore: Option<&KeystoreAccess>,
) -> Result<TrustContext> {
    let strict_key_checking =
        crate::config::resolution::strict_key_checking::resolve_strict_key_checking();
    let is_interactive = tty::is_interactive();
    let (known_keys, recipient_sets) = match loaded {
        Some(loaded) => (loaded.protected.known_keys, loaded.protected.recipient_sets),
        None => (Vec::new(), Vec::new()),
    };
    let self_trust = load_self_trust(self_member_handle, derive_self_sig_x, keystore)?;

    log_trust_context(
        strict_key_checking,
        is_interactive,
        options.allow_non_member,
        active_members_by_kid.len(),
        known_keys.len(),
        recipient_sets.len(),
    );

    Ok(TrustContext {
        known_keys,
        recipient_sets,
        active_members_by_kid,
        self_trust,
        strict_key_checking,
        is_interactive,
        allow_non_member: options.allow_non_member,
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

/// Index the active members a read is authorized against.
///
/// Read through the workspace descriptor the command bound to, so the member
/// set the trust gate consults and the tree the command started in are the same
/// even if the workspace path is repointed while it runs.
fn load_active_member_index_for_read_trust<D>(
    workspace: &D,
    local_key_identity: Option<&LocalKeyIdentity>,
) -> Result<VerifiedActiveMemberIndex>
where
    D: DirectoryFd,
{
    let active_members = load_active_member_files_at(workspace)?;
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

/// Build the self-trust set for this read, falling back to a keystore-less
/// one when the caller passed no keystore.
///
/// A `SelfTrustSet` built through `try_new_with_keystore` can widen itself by
/// consulting the keystore for keys the caller did not already carry;
/// `try_new` cannot, so the caller who reaches `keystore: None` here ends up
/// with a narrower self trust than the keystore-backed path in
/// `load_trust_context` above. The CLI's read path always resolves a
/// `KeyContext` backed by the keystore, so it never takes this branch; a
/// caller reading through a password-derived `CryptoContext` instead does,
/// which is the safer direction for this to narrow in.
fn load_self_trust(
    self_member_handle: &str,
    derive_self_sig_x: Option<[u8; 32]>,
    keystore: Option<&KeystoreAccess>,
) -> Result<SelfTrustSet> {
    match keystore {
        Some(keystore) => SelfTrustSet::try_new_with_keystore(
            self_member_handle,
            derive_self_sig_x,
            keystore.clone(),
        ),
        None => SelfTrustSet::try_new(self_member_handle, derive_self_sig_x),
    }
}
