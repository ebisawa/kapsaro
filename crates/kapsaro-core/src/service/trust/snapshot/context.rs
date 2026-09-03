// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust context loading for write planning.
//! Combines caller-resolved policy values with fixed local-state capabilities.

use std::collections::BTreeMap;

use crate::config::types::{
    StrictKeyChecking, StrictKeyCheckingResolution, StrictKeyCheckingSource,
};
use crate::feature::trust::judgment::SelfTrustSet;
use crate::feature::trust::store_mutation::TrustStoreState;
use crate::model::public_key::PublicKey;
use crate::model::trust_store::{KnownKey, RecipientSetRecord};
use crate::service::operation::OperationOptions;
use crate::service::trust::store::load_session_verified_trust_store;
use crate::service::trust::{CurrentMemberSnapshot, TrustCommandSession, TrustPolicyEvaluator};
use crate::Result;
use tracing::debug;

/// Policy values the caller resolved before invoking a write service.
#[derive(Debug, Clone, Copy)]
pub struct WriteTrustOptions {
    allow_expired_key: bool,
    review_available: bool,
    strict_key_checking: StrictKeyCheckingResolution,
}

impl WriteTrustOptions {
    pub fn new(allow_expired_key: bool, review_available: bool, strict_key_checking: bool) -> Self {
        let strict_key_checking = if strict_key_checking {
            StrictKeyCheckingResolution::strict()
        } else {
            StrictKeyCheckingResolution::explicit(StrictKeyChecking::No)
        };
        Self {
            allow_expired_key,
            review_available,
            strict_key_checking,
        }
    }

    pub fn allow_expired_key(self) -> bool {
        self.allow_expired_key
    }

    pub fn review_available(self) -> bool {
        self.review_available
    }

    pub(crate) fn operation_options(self) -> OperationOptions {
        OperationOptions::new().with_allow_expired_key(self.allow_expired_key)
    }
}

/// Immutable trust state snapshot for a single command execution.
#[derive(Debug, Clone)]
pub struct TrustContext {
    pub known_keys: Vec<KnownKey>,
    pub recipient_sets: Vec<RecipientSetRecord>,
    pub active_members_by_kid: BTreeMap<String, PublicKey>,
    pub self_trust: SelfTrustSet,
    pub strict_key_checking: StrictKeyCheckingResolution,
    pub review_available: bool,
}

pub(super) struct WriteTrustContextLoadResult {
    pub trust_ctx: TrustContext,
    pub evaluator: TrustPolicyEvaluator,
}

pub(crate) fn load_trust_policy_evaluator(
    session: &TrustCommandSession,
    active_members_by_kid: BTreeMap<String, PublicKey>,
) -> Result<TrustPolicyEvaluator> {
    let store = load_session_verified_trust_store(session)?.map(|loaded| loaded.into_store());
    let members = CurrentMemberSnapshot::from_verified_members_by_kid(active_members_by_kid)?;
    Ok(TrustPolicyEvaluator::new(members, store))
}

pub(super) fn load_trust_context(
    options: WriteTrustOptions,
    session: &TrustCommandSession,
    active_members_by_kid: BTreeMap<String, PublicKey>,
) -> Result<WriteTrustContextLoadResult> {
    let loaded = load_session_verified_trust_store(session)?;
    let service_store = loaded.as_ref().map(|loaded| loaded.store().clone());
    let loaded = loaded.map(|loaded| loaded.into_state());
    let members =
        CurrentMemberSnapshot::from_verified_members_by_kid(active_members_by_kid.clone())?;
    let trust_ctx = build_trust_context(options, session, active_members_by_kid, loaded)?;
    Ok(WriteTrustContextLoadResult {
        trust_ctx,
        evaluator: TrustPolicyEvaluator::new(members, service_store),
    })
}

fn build_trust_context(
    options: WriteTrustOptions,
    session: &TrustCommandSession,
    active_members_by_kid: BTreeMap<String, PublicKey>,
    loaded: Option<TrustStoreState>,
) -> Result<TrustContext> {
    let (known_keys, recipient_sets) = match loaded {
        Some(loaded) => (loaded.protected.known_keys, loaded.protected.recipient_sets),
        None => (Vec::new(), Vec::new()),
    };
    let self_trust = SelfTrustSet::try_new_with_keystore(
        session.owner().as_str(),
        Some(session.key_ctx().inner().self_signature_public_key_x()),
        session.keystore().clone(),
    )?;
    log_trust_context(
        options.strict_key_checking,
        options.review_available,
        active_members_by_kid.len(),
        known_keys.len(),
        recipient_sets.len(),
    );
    Ok(TrustContext {
        known_keys,
        recipient_sets,
        active_members_by_kid,
        self_trust,
        strict_key_checking: options.strict_key_checking,
        review_available: options.review_available,
    })
}

fn log_trust_context(
    strict_key_checking: StrictKeyCheckingResolution,
    review_available: bool,
    active_members: usize,
    known_keys: usize,
    recipient_sets: usize,
) {
    debug!(
        "[TRUST] context: strict_key_checking={}, review_available={}, active_members={}, known_keys={}, recipient_sets={}",
        format_strict_key_checking(strict_key_checking),
        review_available,
        active_members,
        known_keys,
        recipient_sets
    );
}

fn format_strict_key_checking(resolution: StrictKeyCheckingResolution) -> &'static str {
    match (resolution.mode, resolution.source) {
        (StrictKeyChecking::Yes, StrictKeyCheckingSource::Default) => "yes/default",
        (StrictKeyChecking::Yes, StrictKeyCheckingSource::ExplicitEnv) => "yes/env",
        (StrictKeyChecking::No, StrictKeyCheckingSource::ExplicitEnv) => "no/env",
        (StrictKeyChecking::No, StrictKeyCheckingSource::Default) => "no/default",
    }
}
