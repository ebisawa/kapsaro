// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Registration state inspection and publication through fixed workspace directories.
//! Validates existing documents before completing a tree or registering a key.

use std::path::PathBuf;

use crate::feature::member::verification::verify_member_public_key_file;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::workspace::members::{
    open_member_documents_at, MemberDocumentWrite, MemberStatus, MemberWriteStore,
};
use crate::io::workspace::setup;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::service::workspace::{WorkspaceAccess, WorkspaceCreationTarget};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

use super::types::{
    ActiveMembershipState, RegistrationMode, RegistrationResult, RegistrationTarget,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitWorkspaceState {
    Bootstrap,
    CompleteStructure,
    NoOp,
}

pub struct InitWorkspaceStatus {
    pub workspace_path: PathBuf,
    pub state: InitWorkspaceState,
}

pub struct RegistrationPaths {
    pub workspace: WorkspaceAccess,
    pub target: RegistrationTarget,
    pub is_new_workspace: bool,
    pub conflict_exists: bool,
}

pub fn evaluate_init_workspace_status(
    target: &WorkspaceCreationTarget,
) -> Result<InitWorkspaceStatus> {
    let mut has_active_members = false;
    let mut complete = false;
    if let Some(workspace) = target.existing_access() {
        complete = setup::inspect_workspace_structure_at(workspace.directory())?;
        has_active_members = verify_registration_members(workspace, MemberStatus::Active)?;
        verify_registration_members(workspace, MemberStatus::Incoming)?;
    }
    Ok(InitWorkspaceStatus {
        workspace_path: target.path().to_path_buf(),
        state: match (has_active_members, complete) {
            (false, _) => InitWorkspaceState::Bootstrap,
            (true, false) => InitWorkspaceState::CompleteStructure,
            (true, true) => InitWorkspaceState::NoOp,
        },
    })
}

fn verify_registration_members(workspace: &WorkspaceAccess, status: MemberStatus) -> Result<bool> {
    let documents = open_member_documents_at(workspace.directory(), status)?;
    for name in documents.names() {
        let document = documents.load_verified_document(name)?;
        let source_name = format_path_relative_to_cwd(&documents.document_path(name));
        verify_member_public_key_file(
            &document.public_key,
            Some(&document.public_key.protected.subject_handle),
            &source_name,
        )?;
    }
    Ok(!documents.names().is_empty())
}

pub fn ensure_init_workspace_structure(
    target: &WorkspaceCreationTarget,
) -> Result<WorkspaceAccess> {
    evaluate_init_workspace_status(target)?;
    let workspace = target.ensure()?;
    setup::ensure_workspace_structure_at(workspace.directory())?;
    Ok(workspace)
}

pub(crate) fn save_registration_member_with_access(
    members: &MemberWriteStore,
    member_handle: &MemberHandle,
    kid: &Kid,
    overwrite: bool,
    keystore: &KeystoreAccess,
    target: RegistrationTarget,
) -> Result<RegistrationResult> {
    let public_key = keystore.load_public_key(member_handle, kid)?;
    let write = members.save(
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
    selection: &WorkspaceCreationTarget,
    mode: RegistrationMode,
    member_handle: &str,
) -> Result<RegistrationPaths> {
    let (workspace, is_new_workspace) = match mode {
        RegistrationMode::Init => {
            let complete = selection
                .existing_access()
                .map(|access| setup::inspect_workspace_structure_at(access.directory()))
                .transpose()?
                .unwrap_or(false);
            (ensure_init_workspace_structure(selection)?, !complete)
        }
        RegistrationMode::Join => (require_join_workspace(selection)?.clone(), false),
    };
    let target = match mode {
        RegistrationMode::Init => RegistrationTarget::Active,
        RegistrationMode::Join => RegistrationTarget::Incoming,
    };
    let documents = open_member_documents_at(workspace.directory(), MemberStatus::from(target))?;
    let conflict_exists = documents.names().contains(&format!("{member_handle}.json"));
    Ok(RegistrationPaths {
        workspace,
        target,
        is_new_workspace,
        conflict_exists,
    })
}

pub(crate) fn require_join_workspace(
    selection: &WorkspaceCreationTarget,
) -> Result<&WorkspaceAccess> {
    let workspace = selection.existing_access().ok_or_else(|| {
        Error::build_not_found_error(format!(
            "Workspace does not exist: {}",
            format_path_relative_to_cwd(selection.path())
        ))
    })?;
    setup::validate_workspace_exists_at(workspace.directory())?;
    Ok(workspace)
}

pub fn resolve_active_membership_state(
    mode: RegistrationMode,
    workspace: &WorkspaceAccess,
    member_handle: &str,
    kid: &str,
) -> Result<ActiveMembershipState> {
    if mode != RegistrationMode::Join {
        return Ok(ActiveMembershipState::None);
    }
    let documents = open_member_documents_at(workspace.directory(), MemberStatus::Active)?;
    let name = format!("{member_handle}.json");
    if !documents.names().contains(&name) {
        return Ok(ActiveMembershipState::None);
    }
    let active_member = documents.load_verified_document(&name)?.public_key;
    Ok(if active_member.protected.kid == kid {
        ActiveMembershipState::SameKey
    } else {
        ActiveMembershipState::DifferentKey
    })
}

fn encode_member_document(public_key: &PublicKey) -> Result<String> {
    serde_json::to_string_pretty(public_key).map_err(Error::build_json_serialization_error)
}
