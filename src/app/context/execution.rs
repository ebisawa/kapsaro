// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::crypto::{load_crypto_context, load_crypto_context_from_env};
use crate::app::context::member::resolve_command_member;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::ResolvedCommandPaths;
use crate::app::context::ssh::ResolvedSshSigningContext;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::context::expiry::{build_key_expiry_warning, build_signing_key_expiry_warning};
use crate::model::identity::MemberId;
use crate::{Error, Result};

/// Fully resolved command execution context.
pub(crate) struct ExecutionContext {
    pub member_id: MemberId,
    pub key_ctx: CryptoContext,
    pub workspace_root: Option<crate::io::workspace::detection::WorkspaceRoot>,
}

impl ExecutionContext {
    /// Resolve workspace, SSH signing context, member ID, and key material for a command.
    fn load_with_signing_context(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        explicit_kid: Option<&str>,
        ssh_ctx: ResolvedSshSigningContext,
    ) -> Result<Self> {
        let resolved = resolve_command_member(options, member_id)?;
        let workspace_root = resolved.paths.workspace_root.clone();
        let key_ctx = load_crypto_context(
            resolved.member_id.as_str(),
            ssh_ctx.backend,
            ssh_ctx.public_key,
            explicit_kid,
            Some(&resolved.paths.keystore_root),
            workspace_root.as_ref().map(|w| w.root_path.clone()),
            options.verbose,
        )?;

        Ok(Self {
            member_id: resolved.member_id,
            key_ctx,
            workspace_root,
        })
    }

    /// Load execution context from environment variables (CI mode).
    pub(crate) fn load_from_env(options: &CommonCommandOptions) -> Result<Self> {
        let resolved = ResolvedCommandPaths::require_workspace(
            options,
            "environment variable key loading (CI mode)",
        )?;
        let workspace_root = resolved.workspace_root.ok_or_else(|| Error::Config {
            message: "Workspace is required for environment variable key loading (CI mode)"
                .to_string(),
        })?;
        let key_ctx =
            load_crypto_context_from_env(workspace_root.root_path.clone(), options.verbose)?;
        let member_id = key_ctx.member_id.clone();

        Ok(Self {
            member_id,
            key_ctx,
            workspace_root: Some(workspace_root),
        })
    }
}

pub(crate) fn resolve_read_execution(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    explicit_kid: Option<&str>,
    ssh_ctx: Option<ResolvedSshSigningContext>,
) -> Result<ExecutionContext> {
    match ssh_ctx {
        Some(ctx) => {
            ExecutionContext::load_with_signing_context(options, member_id, explicit_kid, ctx)
        }
        None => resolve_env_execution(options, member_id, explicit_kid),
    }
}

pub(crate) fn resolve_write_execution(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    ssh_ctx: Option<ResolvedSshSigningContext>,
) -> Result<ExecutionContext> {
    match ssh_ctx {
        Some(ctx) => ExecutionContext::load_with_signing_context(options, member_id, None, ctx),
        None => resolve_env_execution(options, member_id, None),
    }
}

pub(crate) fn build_read_execution_warnings(execution: &ExecutionContext) -> Result<Vec<String>> {
    build_execution_warnings(build_key_expiry_warning(&execution.key_ctx.expires_at)?)
}

pub(crate) fn build_write_execution_warnings(execution: &ExecutionContext) -> Result<Vec<String>> {
    build_execution_warnings(build_signing_key_expiry_warning(
        &execution.key_ctx.expires_at,
    )?)
}

fn resolve_env_execution(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    explicit_kid: Option<&str>,
) -> Result<ExecutionContext> {
    reject_env_member_override(&member_id)?;
    reject_env_kid_override(explicit_kid)?;
    ExecutionContext::load_from_env(options)
}

fn reject_env_member_override(member_id: &Option<String>) -> Result<()> {
    if member_id.is_some() {
        return Err(Error::InvalidArgument {
            message: "--member-id cannot be used in environment variable key mode \
                     (member_id is derived from SECRETENV_PRIVATE_KEY)"
                .to_string(),
        });
    }
    Ok(())
}

fn reject_env_kid_override(explicit_kid: Option<&str>) -> Result<()> {
    if explicit_kid.is_some() {
        return Err(Error::InvalidArgument {
            message: "--kid cannot be used in environment variable key mode \
                     (kid is derived from SECRETENV_PRIVATE_KEY)"
                .to_string(),
        });
    }
    Ok(())
}

fn build_execution_warnings(warning: Option<String>) -> Result<Vec<String>> {
    Ok(warning.into_iter().collect())
}

#[cfg(test)]
#[path = "../../../tests/unit/app_context_env_dispatch_test.rs"]
mod tests;
