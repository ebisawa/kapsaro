// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust-store snapshots used by write reviews.
//! Re-reads the store through the local-state capability fixed by the command.

use crate::model::trust_store::TrustStoreProtected;
use crate::service::trust::store::load_session_trust_store;
use crate::service::trust::{TrustCommandSession, TrustContext};
use crate::{Error, Result};

pub(crate) struct ReviewedTrustStore {
    protected: Option<TrustStoreProtected>,
    changed_message: &'static str,
}

impl ReviewedTrustStore {
    pub(crate) fn from_protected(
        protected: Option<TrustStoreProtected>,
        changed_message: &'static str,
    ) -> Self {
        Self {
            protected,
            changed_message,
        }
    }

    pub(crate) fn load(
        session: &TrustCommandSession,
        trust_context: &TrustContext,
        changed_message: &'static str,
    ) -> Result<Self> {
        let protected = load_reviewed_protected(session)?;
        ensure_trust_context_matches(&protected, trust_context, changed_message)?;
        Ok(Self::from_protected(protected, changed_message))
    }

    pub(crate) fn ensure_current(&self, session: &TrustCommandSession) -> Result<()> {
        let current = load_reviewed_protected(session)?;
        if current == self.protected {
            return Ok(());
        }
        Err(Error::build_invalid_operation_error(
            self.changed_message.to_string(),
        ))
    }
}

fn load_reviewed_protected(session: &TrustCommandSession) -> Result<Option<TrustStoreProtected>> {
    Ok(load_session_trust_store(session)?.map(|state| state.protected))
}

fn ensure_trust_context_matches(
    protected: &Option<TrustStoreProtected>,
    trust_context: &TrustContext,
    changed_message: &'static str,
) -> Result<()> {
    let (known_keys, recipient_sets) = protected
        .as_ref()
        .map(|state| (&state.known_keys[..], &state.recipient_sets[..]))
        .unwrap_or_default();
    if known_keys == trust_context.known_keys && recipient_sets == trust_context.recipient_sets {
        return Ok(());
    }
    Err(Error::build_invalid_operation_error(
        changed_message.to_string(),
    ))
}
