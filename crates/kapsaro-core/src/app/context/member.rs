// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member resolution against the local keystore.
//! Turns an optional handle into the one member a command will act as.

use crate::app::context::identity::build_missing_member_handle_error;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::CommandPathResolution;
use crate::app::keystore::open_local_keystore_at;
use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::config::resolution::member_handle::MemberHandleResolver;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::helpers::find_member_by_kid;
use crate::model::identity::MemberHandle;
use crate::support::fs::anchor::AnchoredDir;
use crate::Result;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct CommandMemberResolution {
    pub member_handle: MemberHandle,
    pub paths: CommandPathResolution,
    pub(crate) keystore_access: KeystoreAccess,
}

pub fn resolve_command_member(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<CommandMemberResolution> {
    let paths = CommandPathResolution::load(options)?;
    let keystore_access = open_local_keystore_at(paths.home())?;
    let member_handle = MemberHandleResolver::fixed(&paths.global_config, Some(&keystore_access))
        .resolve(member_handle)?
        .ok_or_else(|| build_missing_member_handle_error(false))?;
    debug!("[CTX] member_handle={}", member_handle);
    Ok(CommandMemberResolution {
        member_handle,
        paths,
        keystore_access,
    })
}

pub(crate) fn resolve_required_member_with_access(
    access: &KeystoreAccess,
    member_handle: Option<String>,
) -> Result<MemberHandle> {
    resolve_member_with_access(access, member_handle)?
        .ok_or_else(|| build_missing_member_handle_error(false))
}

pub(crate) fn resolve_required_member_with_optional_access(
    home: Option<&AnchoredDir>,
    access: Option<&KeystoreAccess>,
    member_handle: Option<String>,
) -> Result<MemberHandle> {
    MemberHandleResolver::fixed(&GlobalConfigSnapshot::for_home(home), access)
        .resolve(member_handle)?
        .ok_or_else(|| build_missing_member_handle_error(false))
}

/// Resolve the member a named key belongs to.
///
/// The configured sources answer first, and a keystore that names no member
/// there is searched for the key itself. A handle the caller passed always
/// comes back as it was, so the search only runs for a command that named none.
pub(crate) fn resolve_key_owner_with_access(
    access: &KeystoreAccess,
    member_handle: Option<String>,
    kid: &str,
) -> Result<MemberHandle> {
    match resolve_member_with_access(access, member_handle)? {
        Some(member_handle) => Ok(member_handle),
        None => find_member_by_kid(access, kid),
    }
}

/// Resolve the configured member, falling back to a single-member keystore.
///
/// The configuration is read through the home the keystore was opened from, so a
/// `KeystoreAccess` carrying no home resolves against an empty configuration and
/// a configured `member_handle` is passed over without a word. Every caller here
/// opens its keystore from a home, so that is unreachable today; a keystore
/// opened another way has to be given its own configuration source instead of
/// relying on this one.
fn resolve_member_with_access(
    access: &KeystoreAccess,
    member_handle: Option<String>,
) -> Result<Option<MemberHandle>> {
    MemberHandleResolver::fixed(&GlobalConfigSnapshot::for_home(access.home()), Some(access))
        .resolve(member_handle)
}
