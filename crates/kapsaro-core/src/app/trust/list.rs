// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust list command resolution and result construction.
//! Keeps owner and local-state directory capabilities fixed across retries.

use std::path::Path;
use std::sync::Arc;

use crate::app::context::member::resolve_required_member_with_optional_access;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::load_optional_trust_store;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::trust::paths::{get_trust_store_file_path, TRUST_DIR_NAME};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::{KnownKey, RecipientSetRecord, TrustStoreProtected};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_optional_child_dir, DirectoryFd, DirectoryScope, OpenDir};
use crate::Result;

#[derive(Debug, Clone)]
pub struct TrustListItem {
    pub kid: Kid,
    pub member_handle: MemberHandle,
    pub approved_at: String,
    pub approved_via: String,
}

#[derive(Debug, Clone)]
pub struct RecipientSetListItem {
    pub sid: String,
    pub recipient_kids: Vec<String>,
    pub recipient_set_hash: String,
    pub approved_at: String,
    pub approved_via: String,
}

/// Result of trust list command.
#[derive(Debug)]
pub struct TrustListResult {
    pub items: Vec<TrustListItem>,
}

#[derive(Debug)]
pub struct RecipientSetListResult {
    pub items: Vec<RecipientSetListItem>,
}

/// Resolved owner and local-state capabilities for one trust list invocation.
#[derive(Debug)]
pub struct TrustListCommand {
    owner: MemberHandle,
    path: std::path::PathBuf,
    state: TrustListState,
}

#[derive(Debug)]
enum TrustListState {
    Absent,
    Opened {
        home: AnchoredDir,
        keystore: Option<KeystoreAccess>,
        trust_dir: Option<Arc<OpenDir>>,
    },
}

impl From<&KnownKey> for TrustListItem {
    fn from(known_key: &KnownKey) -> Self {
        Self {
            kid: Kid::try_from(known_key.kid.clone()).expect("known key kid must be valid"),
            member_handle: MemberHandle::try_from(known_key.subject_handle.clone())
                .expect("known key member_handle must be valid"),
            approved_at: known_key.approved_at.clone(),
            approved_via: known_key.approved_via.to_string(),
        }
    }
}

impl From<&RecipientSetRecord> for RecipientSetListItem {
    fn from(record: &RecipientSetRecord) -> Self {
        Self {
            sid: record.sid.clone(),
            recipient_kids: record.recipient_kids.clone(),
            recipient_set_hash: record.recipient_set_hash.clone(),
            approved_at: record.approved_at.clone(),
            approved_via: record.approved_via.to_string(),
        }
    }
}

/// Name the store a listing would read when there is no local state at all.
///
/// Listing an absent store is an empty result rather than a failure, so the
/// owner still has to be resolved to say which file was looked for.
fn build_absent_trust_list_command(
    base_dir: &Path,
    member_handle: Option<String>,
) -> Result<TrustListCommand> {
    let owner = resolve_required_member_with_optional_access(None, None, member_handle)?;
    let path = get_trust_store_file_path(base_dir, &owner);
    Ok(TrustListCommand {
        owner,
        path,
        state: TrustListState::Absent,
    })
}

pub fn resolve_trust_list_command(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<TrustListCommand> {
    let base_dir = options.resolve_base_dir()?;
    let Some(home) =
        AnchoredDir::open_optional(&base_dir, DirectoryScope::LocalState, "local state root")?
    else {
        return build_absent_trust_list_command(&base_dir, member_handle);
    };
    // An absent keystore is only tolerable while there is no store to verify: a
    // listing that finds a trust store still requires one, and reports it
    // missing rather than showing content whose signature it never checked.
    let keystore = KeystoreAccess::open_optional_from_anchored_home(&home)?;
    let owner = resolve_required_member_with_optional_access(
        Some(&home),
        keystore.as_ref(),
        member_handle,
    )?;
    let path = get_trust_store_file_path(home.path(), &owner);
    let trust_dir = open_optional_child_dir(&home, TRUST_DIR_NAME)?.map(Arc::new);
    Ok(TrustListCommand {
        owner,
        path,
        state: TrustListState::Opened {
            home,
            keystore,
            trust_dir,
        },
    })
}

pub fn list_known_keys_command(command: &TrustListCommand) -> Result<TrustListResult> {
    let entries = load_trust_store_list_entries_command(command, |protected| {
        protected
            .known_keys
            .iter()
            .map(TrustListItem::from)
            .collect()
    })?;
    Ok(TrustListResult { items: entries })
}

pub fn list_recipient_sets_command(command: &TrustListCommand) -> Result<RecipientSetListResult> {
    let entries = load_trust_store_list_entries_command(command, |protected| {
        protected
            .recipient_sets
            .iter()
            .map(RecipientSetListItem::from)
            .collect()
    })?;
    Ok(RecipientSetListResult { items: entries })
}

fn load_trust_store_list_entries_command<T>(
    command: &TrustListCommand,
    build_items: impl FnOnce(&TrustStoreProtected) -> Vec<T>,
) -> Result<Vec<T>> {
    let TrustListState::Opened {
        home,
        keystore,
        trust_dir,
    } = &command.state
    else {
        return Ok(Vec::new());
    };
    let loaded = load_optional_trust_store(
        home,
        trust_dir.as_deref(),
        &command.owner,
        keystore.as_ref(),
    )?;
    let Some(loaded) = loaded else {
        return Ok(Vec::new());
    };
    Ok(build_items(&loaded.protected))
}

impl TrustListCommand {
    pub(super) fn owner(&self) -> &MemberHandle {
        &self.owner
    }

    /// The local state root the trust directory was opened under.
    ///
    /// A read below the trust directory reports a refused permission against
    /// this root as well, so the operator is told which directory in the chain
    /// stopped it.
    pub(super) fn home(&self) -> Option<&AnchoredDir> {
        match &self.state {
            TrustListState::Absent => None,
            TrustListState::Opened { home, .. } => Some(home),
        }
    }

    pub(super) fn trust_dir(&self) -> Option<&Arc<OpenDir>> {
        match &self.state {
            TrustListState::Absent => None,
            TrustListState::Opened { trust_dir, .. } => trust_dir.as_ref(),
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_list_test.rs"]
mod tests;
