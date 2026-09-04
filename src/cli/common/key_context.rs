// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI resolution for key contexts used by workspace read and write commands.
//! Captures environment-key secrets and loads filesystem-backed signing keys.

use std::path::Path;

use crate::cli::common::command::require_member_handle;
use crate::cli::common::context::CliContext;
use kapsaro_core::api::key::{KeyContext, Kid, LocalKeyContextRequest, MemberHandle};
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::api::trust::TrustCommandSession;
use kapsaro_core::{Error, Result};
use tracing::debug;

const ENV_PRIVATE_KEY: &str = "KAPSARO_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "KAPSARO_KEY_PASSWORD";

pub(crate) fn load_read_key_context(
    context: &CliContext,
    workspace_path: &Path,
    member_handle: Option<String>,
    kid: Option<&str>,
) -> Result<KeyContext> {
    if std::env::var_os(ENV_PRIVATE_KEY).is_some() {
        debug!("[CTX] execution mode=env-key");
        return load_environment_key(workspace_path, member_handle, kid);
    }
    debug!("[CTX] execution mode=local-key");
    load_local_key(context, workspace_path, member_handle, kid)
}

/// Load a filesystem-backed signing key from explicit CLI-resolved inputs.
pub(crate) fn load_signing_key_context(
    context: &CliContext,
    member_handle: Option<String>,
    kid: Option<&str>,
) -> Result<KeyContext> {
    let member = require_member_handle(context.member_handle(member_handle)?, false)?;
    let member = MemberHandle::try_from(member)?;
    let store = context.local_state()?.require_key_store(&member)?;
    let request = local_key_request(context, member, kid)?;
    store.load_selected_key_context(request)
}

/// Bind one local signing key and its local-state home for a trust command.
pub(crate) fn load_trust_command_session(
    context: &CliContext,
    member_handle: Option<String>,
) -> Result<TrustCommandSession> {
    let member = require_member_handle(context.member_handle(member_handle)?, false)?;
    let member = MemberHandle::try_from(member)?;
    let local_state = context.local_state()?;
    let store = local_state.require_key_store(&member)?;
    let request = local_key_request(context, member.clone(), None)?;
    let key_context = store.load_selected_key_context(request)?;
    TrustCommandSession::open(local_state, member, key_context)
}

fn load_environment_key(
    workspace_path: &Path,
    member_handle: Option<String>,
    kid: Option<&str>,
) -> Result<KeyContext> {
    enforce_environment_identity_absent(member_handle, kid)?;
    debug!("[ENV_KEY] load private key: start");
    let _cleanup = EnvironmentKeyCleanup;
    let encoded = load_secret_environment(ENV_PRIVATE_KEY, false)?;
    debug!("[ENV_KEY] load private key: private key env present");
    let password = load_secret_environment(ENV_KEY_PASSWORD, true)?;
    debug!("[ENV_KEY] load private key: password env present");
    KeyContext::load_environment_key(encoded, password, workspace_path.to_path_buf())
}

fn load_local_key(
    context: &CliContext,
    workspace_path: &Path,
    member_handle: Option<String>,
    kid: Option<&str>,
) -> Result<KeyContext> {
    let member = require_member_handle(context.member_handle(member_handle)?, false)?;
    let member = MemberHandle::try_from(member)?;
    let store = context.local_state()?.require_key_store(&member)?;
    let request =
        local_key_request(context, member, kid)?.with_workspace_path(workspace_path.to_path_buf());
    store.load_selected_key_context(request)
}

fn local_key_request(
    context: &CliContext,
    member: MemberHandle,
    kid: Option<&str>,
) -> Result<LocalKeyContextRequest> {
    let mut request = LocalKeyContextRequest::new(member, context.ssh_signing_inputs()?);
    if let Some(kid) = kid {
        request = request.with_kid(Kid::try_from(kid.to_string())?);
    }
    Ok(request)
}

fn load_secret_environment(name: &str, password: bool) -> Result<SecretString> {
    std::env::var(name)
        .map(SecretString::new)
        .map_err(|error| environment_error(name, password, error))
}

fn environment_error(name: &str, password: bool, error: std::env::VarError) -> Error {
    match error {
        std::env::VarError::NotPresent if password => Error::build_config_error(format!(
            "{name} environment variable is required when {ENV_PRIVATE_KEY} is set"
        )),
        std::env::VarError::NotPresent => {
            Error::build_config_error(format!("{name} environment variable is not set"))
        }
        std::env::VarError::NotUnicode(_) => Error::build_config_error(format!(
            "{name} environment variable contains invalid UTF-8"
        )),
    }
}

fn enforce_environment_identity_absent(
    member_handle: Option<String>,
    kid: Option<&str>,
) -> Result<()> {
    if member_handle.is_some() {
        return Err(Error::build_invalid_argument_error(
            "--member-handle cannot be used in environment variable key mode \
             (member handle is derived from KAPSARO_PRIVATE_KEY)",
        ));
    }
    if kid.is_some() {
        return Err(Error::build_invalid_argument_error(
            "--kid cannot be used in environment variable key mode \
             (kid is derived from KAPSARO_PRIVATE_KEY)",
        ));
    }
    Ok(())
}

struct EnvironmentKeyCleanup;

impl Drop for EnvironmentKeyCleanup {
    fn drop(&mut self) {
        std::env::remove_var(ENV_PRIVATE_KEY);
        std::env::remove_var(ENV_KEY_PASSWORD);
        debug!("[ENV_KEY] cleanup private key environment");
    }
}
