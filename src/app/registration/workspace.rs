// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::app::context::options::CommonCommandOptions;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::keystore::storage::load_public_key;
use crate::io::workspace::detection::resolve_workspace_creation_path;
use crate::io::workspace::members::{
    ensure_member_document_kid_is_unique, get_active_member_file_path,
    get_incoming_member_file_path, load_verified_member_file_from_path, MemberStatus,
};
use crate::io::workspace::setup;
use crate::Result;

use super::types::{
    ActiveMembershipState, RegistrationMode, RegistrationResult, RegistrationTarget,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitWorkspaceState {
    Bootstrap,
    NoOp,
}

pub(crate) struct InitWorkspaceStatus {
    pub workspace_path: PathBuf,
    pub state: InitWorkspaceState,
}

pub(crate) struct RegistrationPaths {
    pub workspace_path: PathBuf,
    pub keystore_root: PathBuf,
    pub target: RegistrationTarget,
    pub is_new_workspace: bool,
    pub conflict_exists: bool,
}

pub(crate) fn evaluate_init_workspace_status(
    common: &CommonCommandOptions,
) -> Result<InitWorkspaceStatus> {
    let workspace_path = resolve_workspace_creation_path(common.workspace.clone())?;
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

pub(crate) fn ensure_init_workspace_structure(workspace_path: &Path) -> Result<()> {
    setup::ensure_workspace_structure(workspace_path)?;
    Ok(())
}

pub(crate) fn save_registration_member(
    workspace_path: &Path,
    member_id: &str,
    kid: &str,
    overwrite: bool,
    keystore_root: &Path,
    target: RegistrationTarget,
) -> Result<RegistrationResult> {
    let member_file = member_file_path(workspace_path, member_id, target);

    if !member_file.exists() {
        save_member_document(
            &member_file,
            workspace_path,
            member_id,
            kid,
            false,
            keystore_root,
            target,
        )?;
        return Ok(RegistrationResult::NewMember);
    }

    if overwrite {
        save_member_document(
            &member_file,
            workspace_path,
            member_id,
            kid,
            true,
            keystore_root,
            target,
        )?;
        return Ok(RegistrationResult::Updated);
    }

    Ok(RegistrationResult::AlreadyExists)
}

pub(crate) fn resolve_registration_paths(
    common: &CommonCommandOptions,
    mode: RegistrationMode,
    member_id: &str,
) -> Result<RegistrationPaths> {
    let workspace_path = resolve_workspace_creation_path(common.workspace.clone())?;
    let is_new_workspace = resolve_workspace_for_registration(mode, &workspace_path)?;
    let keystore_root = KeystoreResolver::resolve(common.home.as_ref())?;
    let target = registration_target(mode);
    let conflict_exists =
        member_file_path(&workspace_path, member_id, RegistrationTarget::from(target)).exists();
    Ok(RegistrationPaths {
        workspace_path,
        keystore_root,
        target: RegistrationTarget::from(target),
        is_new_workspace,
        conflict_exists,
    })
}

pub(crate) fn resolve_active_membership_state(
    mode: RegistrationMode,
    workspace_path: &Path,
    member_id: &str,
    kid: &str,
) -> Result<ActiveMembershipState> {
    if mode != RegistrationMode::Join {
        return Ok(ActiveMembershipState::None);
    }

    let active_path = get_active_member_file_path(workspace_path, member_id);
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

fn member_file_path(workspace_path: &Path, member_id: &str, target: RegistrationTarget) -> PathBuf {
    match target {
        RegistrationTarget::Active => get_active_member_file_path(workspace_path, member_id),
        RegistrationTarget::Incoming => get_incoming_member_file_path(workspace_path, member_id),
    }
}

fn save_member_document(
    member_file: &Path,
    workspace_path: &Path,
    member_id: &str,
    kid: &str,
    overwrite: bool,
    keystore_root: &Path,
    target: RegistrationTarget,
) -> Result<()> {
    let public_key = load_public_key(keystore_root, member_id, kid)?;
    let status = match target {
        RegistrationTarget::Active => MemberStatus::Active,
        RegistrationTarget::Incoming => MemberStatus::Incoming,
    };
    ensure_member_document_kid_is_unique(
        workspace_path,
        status,
        member_id,
        &public_key.protected.kid,
        overwrite && member_file.exists(),
    )?;
    setup::save_member_document(member_file, &public_key)
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
