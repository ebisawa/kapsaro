// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::identity::{
    build_missing_member_id_error, require_member_id_input, resolve_member_id_input,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::ResolvedCommandPaths;
use crate::io::keystore::storage;
use crate::model::identity::MemberId;
use crate::Result;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedCommandMember {
    pub member_id: MemberId,
    pub paths: ResolvedCommandPaths,
}

pub(crate) fn resolve_command_member(
    options: &CommonCommandOptions,
    member_id: Option<String>,
) -> Result<ResolvedCommandMember> {
    let paths = ResolvedCommandPaths::load(options)?;
    let member_id = MemberId::try_from(require_member_id_input(
        member_id,
        Some(paths.base_dir.as_path()),
        false,
    )?)?;
    Ok(ResolvedCommandMember { member_id, paths })
}

pub(crate) fn resolve_required_member(
    options: &CommonCommandOptions,
    member_id: Option<String>,
) -> Result<String> {
    let paths = ResolvedCommandPaths::load(options)?;
    require_member_id_input(member_id, Some(paths.base_dir.as_path()), false)
}

pub(crate) fn resolve_key_owner(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: &str,
) -> Result<String> {
    let paths = ResolvedCommandPaths::load(options)?;
    match resolve_member_id_input(member_id.clone(), Some(paths.base_dir.as_path())) {
        Ok(Some(member_id)) => Ok(member_id),
        Ok(None) if member_id.is_none() => storage::find_member_by_kid(&paths.keystore_root, kid),
        Ok(None) => Err(build_missing_member_id_error(false)),
        Err(error) => Err(error),
    }
}
