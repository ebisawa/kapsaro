// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace state and paths for registration.
//! Reports what already exists so registration only creates what is missing.

use std::path::{Path, PathBuf};

use crate::app::context::options::CommonCommandOptions;
use crate::config::resolution::workspace::resolve_workspace_path_from_sources;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::workspace::detection::resolve_workspace_creation_path;
use crate::io::workspace::members::{
    get_active_member_file_path, get_incoming_member_file_path,
    load_verified_member_file_from_path, save_member_content_keeping_existing, MemberDocumentWrite,
    MemberStatus,
};
use crate::io::workspace::setup;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::DirectoryScope;
use crate::{Error, Result};

use super::types::{
    ActiveMembershipState, RegistrationMode, RegistrationResult, RegistrationTarget,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitWorkspaceState {
    Bootstrap,
    NoOp,
}

pub struct InitWorkspaceStatus {
    pub workspace_path: PathBuf,
    pub state: InitWorkspaceState,
}

pub struct RegistrationPaths {
    pub workspace_path: PathBuf,
    pub target: RegistrationTarget,
    pub is_new_workspace: bool,
    pub conflict_exists: bool,
}

pub fn evaluate_init_workspace_status(
    common: &CommonCommandOptions,
) -> Result<InitWorkspaceStatus> {
    let workspace_path = resolve_registration_workspace_path(common)?;
    let has_active_members = setup::check_workspace_has_active_members(&workspace_path)?;
    if has_active_members {
        return Ok(InitWorkspaceStatus {
            workspace_path,
            state: InitWorkspaceState::NoOp,
        });
    }

    Ok(InitWorkspaceStatus {
        workspace_path,
        state: InitWorkspaceState::Bootstrap,
    })
}

pub fn ensure_init_workspace_structure(workspace_path: &Path) -> Result<()> {
    setup::ensure_workspace_structure(workspace_path)?;
    Ok(())
}

/// Publish the registering member's public key into the workspace.
///
/// The workspace is bound to a descriptor before the write, so the document
/// lands in the tree this registration resolved rather than in whatever the
/// workspace path names by the time the member store takes its lock. The member
/// store then settles the kid uniqueness check, the name it writes and the write
/// itself under one lock, so what came back is what the write met: two
/// registrations of the same kid cannot both pass a check taken before either of
/// them landed.
pub(crate) fn save_registration_member_with_access(
    workspace_path: &Path,
    member_handle: &MemberHandle,
    kid: &Kid,
    overwrite: bool,
    keystore: &KeystoreAccess,
    target: RegistrationTarget,
) -> Result<RegistrationResult> {
    let public_key = keystore.load_public_key(member_handle, kid)?;
    let workspace_dir = AnchoredDir::open(
        workspace_path.to_path_buf(),
        DirectoryScope::Generic,
        "workspace root",
    )?;
    let write = save_member_content_keeping_existing(
        &workspace_dir,
        MemberStatus::from(target),
        member_handle.as_str(),
        &encode_member_document(&public_key)?,
        overwrite,
    )?;
    Ok(match write {
        MemberDocumentWrite::Created => RegistrationResult::NewMember,
        MemberDocumentWrite::Replaced => RegistrationResult::Updated,
        MemberDocumentWrite::Kept => RegistrationResult::AlreadyExists,
    })
}

pub fn resolve_registration_paths(
    common: &CommonCommandOptions,
    mode: RegistrationMode,
    member_handle: &str,
) -> Result<RegistrationPaths> {
    let workspace_path = resolve_registration_workspace_path(common)?;
    let is_new_workspace = resolve_workspace_for_registration(mode, &workspace_path)?;
    let target = registration_target(mode);
    let conflict_exists = member_file_path(
        &workspace_path,
        member_handle,
        RegistrationTarget::from(target),
    )
    .exists();
    Ok(RegistrationPaths {
        workspace_path,
        target: RegistrationTarget::from(target),
        is_new_workspace,
        conflict_exists,
    })
}

fn resolve_registration_workspace_path(common: &CommonCommandOptions) -> Result<PathBuf> {
    match resolve_workspace_path_from_sources(common.workspace.clone(), common.global_config()?)? {
        Some(resolution) => Ok(resolution.path),
        None => resolve_workspace_creation_path(None),
    }
}

pub fn resolve_active_membership_state(
    mode: RegistrationMode,
    workspace_path: &Path,
    member_handle: &str,
    kid: &str,
) -> Result<ActiveMembershipState> {
    if mode != RegistrationMode::Join {
        return Ok(ActiveMembershipState::None);
    }

    let active_path = get_active_member_file_path(workspace_path, member_handle);
    if !active_path.exists() {
        return Ok(ActiveMembershipState::None);
    }

    let active_member = load_verified_member_file_from_path(&active_path)?;
    if active_member.protected.kid == kid {
        Ok(ActiveMembershipState::SameKey)
    } else {
        Ok(ActiveMembershipState::DifferentKey)
    }
}

fn member_file_path(
    workspace_path: &Path,
    member_handle: &str,
    target: RegistrationTarget,
) -> PathBuf {
    match target {
        RegistrationTarget::Active => get_active_member_file_path(workspace_path, member_handle),
        RegistrationTarget::Incoming => {
            get_incoming_member_file_path(workspace_path, member_handle)
        }
    }
}

fn encode_member_document(public_key: &PublicKey) -> Result<String> {
    serde_json::to_string_pretty(public_key).map_err(Error::build_json_serialization_error)
}

fn resolve_workspace_for_registration(
    mode: RegistrationMode,
    workspace_path: &Path,
) -> Result<bool> {
    match mode {
        RegistrationMode::Init => setup::ensure_workspace_structure(workspace_path),
        RegistrationMode::Join => {
            setup::validate_workspace_exists(workspace_path)?;
            Ok(false)
        }
    }
}

fn registration_target(mode: RegistrationMode) -> MemberStatus {
    match mode {
        RegistrationMode::Init => MemberStatus::Active,
        RegistrationMode::Join => MemberStatus::Incoming,
    }
}
