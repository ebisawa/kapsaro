// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::identity::{
    build_missing_member_handle_error, require_member_handle_input, resolve_member_handle_input,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::CommandPathResolution;
use crate::io::keystore::storage;
use crate::model::identity::MemberHandle;
use crate::Result;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct CommandMemberResolution {
    pub member_handle: MemberHandle,
    pub paths: CommandPathResolution,
}

pub fn resolve_command_member(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<CommandMemberResolution> {
    let paths = CommandPathResolution::load(options)?;
    let member_handle = MemberHandle::try_from(require_member_handle_input(
        member_handle,
        Some(paths.base_dir.as_path()),
        false,
    )?)?;
    if options.debug {
        debug!("[CTX] member_handle={}", member_handle);
    }
    Ok(CommandMemberResolution {
        member_handle,
        paths,
    })
}

pub fn resolve_required_member(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<String> {
    let paths = CommandPathResolution::load(options)?;
    require_member_handle_input(member_handle, Some(paths.base_dir.as_path()), false)
}

pub fn resolve_key_owner(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    kid: &str,
) -> Result<String> {
    let paths = CommandPathResolution::load(options)?;
    match resolve_member_handle_input(member_handle.clone(), Some(paths.base_dir.as_path())) {
        Ok(Some(member_handle)) => Ok(member_handle),
        Ok(None) if member_handle.is_none() => {
            storage::find_member_by_kid(&paths.keystore_root, kid)
        }
        Ok(None) => Err(build_missing_member_handle_error(false)),
        Err(error) => Err(error),
    }
}
