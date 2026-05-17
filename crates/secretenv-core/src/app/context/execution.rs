// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::crypto::{load_crypto_context, load_crypto_context_from_env};
use crate::app::context::member::resolve_command_member;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::CommandPathResolution;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::context::expiry::{build_key_expiry_warning, build_signing_key_expiry_warning};
use crate::model::identity::MemberHandle;
use crate::{Error, Result};
use tracing::debug;

/// Fully resolved command execution context.
pub struct ExecutionContext {
    pub member_handle: MemberHandle,
    pub key_ctx: CryptoContext,
    pub workspace_root: Option<crate::io::workspace::detection::WorkspaceRoot>,
}

impl ExecutionContext {
    /// Resolve workspace, SSH signing context, member handle, and key material for a command.
    fn load_with_signing_context(
        options: &CommonCommandOptions,
        member_handle: Option<String>,
        explicit_kid: Option<&str>,
        ssh_ctx: SshSigningContextResolution,
    ) -> Result<Self> {
        if options.debug {
            debug!("[CTX] execution mode=ssh-backed");
        }
        let resolved = resolve_command_member(options, member_handle)?;
        let workspace_root = resolved.paths.workspace_root.clone();
        let key_ctx = load_crypto_context(
            resolved.member_handle.as_str(),
            ssh_ctx.backend,
            ssh_ctx.public_key,
            explicit_kid,
            Some(&resolved.paths.keystore_root),
            workspace_root.as_ref().map(|w| w.root_path.clone()),
            options.debug,
        )?;

        Ok(Self {
            member_handle: resolved.member_handle,
            key_ctx,
            workspace_root,
        })
    }

    /// Load execution context from environment variables (CI mode).
    pub fn load_from_env(options: &CommonCommandOptions) -> Result<Self> {
        if options.debug {
            debug!("[CTX] execution mode=env-key");
        }
        let resolved = CommandPathResolution::require_workspace(
            options,
            "environment variable key loading (CI mode)",
        )?;
        let workspace_root = resolved.workspace_root.ok_or_else(|| {
            Error::build_config_error(
                "Workspace is required for environment variable key loading (CI mode)".to_string(),
            )
        })?;
        let key_ctx =
            load_crypto_context_from_env(workspace_root.root_path.clone(), options.debug)?;
        let member_handle = key_ctx.member_handle.clone();

        Ok(Self {
            member_handle,
            key_ctx,
            workspace_root: Some(workspace_root),
        })
    }
}

pub fn resolve_read_execution(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    explicit_kid: Option<&str>,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<ExecutionContext> {
    match ssh_ctx {
        Some(ctx) => {
            ExecutionContext::load_with_signing_context(options, member_handle, explicit_kid, ctx)
        }
        None => resolve_env_execution(options, member_handle, explicit_kid),
    }
}

pub fn resolve_write_execution(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<ExecutionContext> {
    match ssh_ctx {
        Some(ctx) => ExecutionContext::load_with_signing_context(options, member_handle, None, ctx),
        None => resolve_env_execution(options, member_handle, None),
    }
}

pub fn build_read_execution_warnings(execution: &ExecutionContext) -> Result<Vec<String>> {
    build_execution_warnings(build_key_expiry_warning(&execution.key_ctx.expires_at)?)
}

pub fn build_write_execution_warnings(execution: &ExecutionContext) -> Result<Vec<String>> {
    build_execution_warnings(build_signing_key_expiry_warning(
        &execution.key_ctx.expires_at,
    )?)
}

fn resolve_env_execution(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    explicit_kid: Option<&str>,
) -> Result<ExecutionContext> {
    enforce_env_member_handle_absent(&member_handle)?;
    enforce_env_kid_absent(explicit_kid)?;
    ExecutionContext::load_from_env(options)
}

fn enforce_env_member_handle_absent(member_handle: &Option<String>) -> Result<()> {
    if member_handle.is_some() {
        return Err(Error::build_invalid_argument_error(
            "--member-handle cannot be used in environment variable key mode \
                     (member handle is derived from SECRETENV_PRIVATE_KEY)"
                .to_string(),
        ));
    }
    Ok(())
}

fn enforce_env_kid_absent(explicit_kid: Option<&str>) -> Result<()> {
    if explicit_kid.is_some() {
        return Err(Error::build_invalid_argument_error(
            "--kid cannot be used in environment variable key mode \
                     (kid is derived from SECRETENV_PRIVATE_KEY)"
                .to_string(),
        ));
    }
    Ok(())
}

fn build_execution_warnings(warning: Option<String>) -> Result<Vec<String>> {
    Ok(warning.into_iter().collect())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_context_env_dispatch_test.rs"]
mod tests;
