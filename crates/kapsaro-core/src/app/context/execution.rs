// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::api::key::KeyContext;
use crate::api::key::LocalKeyStore;
use crate::api::trust::{CurrentMemberSnapshot, LocalTrustStore, TrustPolicyEvaluator};
use crate::app::context::crypto::{load_crypto_context, load_crypto_context_from_env};
use crate::app::context::member::resolve_command_member;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::CommandPathResolution;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::feature::context::crypto::{CryptoContext, LocalKeyIdentity};
use crate::feature::envelope::wrap_set::WrapSet;
use crate::model::identity::MemberHandle;
use crate::{Error, Result};
use tracing::debug;

/// Fully resolved command execution context.
pub struct ExecutionContext {
    pub member_handle: MemberHandle,
    pub key_ctx: KeyContext,
    pub workspace_root: Option<crate::io::workspace::detection::WorkspaceRoot>,
}

pub(crate) struct SelectedDecryptionKeyExpiry {
    pub(crate) warning: Option<String>,
    pub(crate) key_identity: LocalKeyIdentity,
}

impl ExecutionContext {
    /// Resolve workspace, SSH signing context, member handle, and key material for a command.
    fn load_with_signing_context(
        options: &CommonCommandOptions,
        member_handle: Option<String>,
        explicit_kid: Option<&str>,
        ssh_ctx: SshSigningContextResolution,
    ) -> Result<Self> {
        debug!("[CTX] execution mode=ssh-backed");
        let resolved = resolve_command_member(options, member_handle)?;
        let workspace_root = resolved.paths.workspace_root.clone();
        let key_ctx = load_crypto_context(
            resolved.member_handle.as_str(),
            ssh_ctx.backend,
            ssh_ctx.public_key,
            explicit_kid,
            Some(&resolved.paths.keystore_root),
            workspace_root.as_ref().map(|w| w.root_path.clone()),
        )?;

        Ok(Self {
            member_handle: resolved.member_handle,
            key_ctx: KeyContext::from_inner(key_ctx),
            workspace_root,
        })
    }

    /// Load execution context from environment variables (CI mode).
    pub fn load_from_env(options: &CommonCommandOptions) -> Result<Self> {
        debug!("[CTX] execution mode=env-key");
        let resolved = CommandPathResolution::require_workspace(
            options,
            "environment variable key loading (CI mode)",
        )?;
        let workspace_root = resolved.into_required_workspace_root();
        let key_ctx = load_crypto_context_from_env(workspace_root.root_path.clone())?;
        let member_handle = key_ctx.member_handle_id().clone();

        Ok(Self {
            member_handle,
            key_ctx: KeyContext::from_inner(key_ctx),
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

pub fn resolve_read_trust_evaluator(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
) -> Result<TrustPolicyEvaluator> {
    let workspace = execution.workspace_root.as_ref().ok_or_else(|| {
        Error::build_invalid_operation_error(
            "Workspace is required for read trust evaluation".to_string(),
        )
    })?;
    let members = CurrentMemberSnapshot::load(&workspace.root_path)?;
    let base_dir = options.resolve_base_dir()?;
    let trust_store = LocalTrustStore::new(base_dir, execution.member_handle.to_string());
    let key_store = LocalKeyStore::new(options.resolve_keystore_root()?);
    let store = trust_store
        .load_verified(&key_store)?
        .map(|loaded| loaded.into_store());
    Ok(TrustPolicyEvaluator::new(members, store))
}

pub fn build_write_execution_warnings(execution: &ExecutionContext) -> Result<Vec<String>> {
    build_execution_warnings(
        execution
            .key_ctx
            .inner()
            .build_signing_key_expiry_warning()?,
    )
}

pub fn enforce_selected_decryption_key_expiry(
    execution: &ExecutionContext,
    wrap_set: &WrapSet,
    allow_expired_key: bool,
) -> Result<Option<String>> {
    Ok(evaluate_selected_decryption_key_expiry(execution, wrap_set, allow_expired_key)?.warning)
}

pub(crate) fn evaluate_selected_decryption_key_expiry(
    execution: &ExecutionContext,
    wrap_set: &WrapSet,
    allow_expired_key: bool,
) -> Result<SelectedDecryptionKeyExpiry> {
    let selected = execution
        .key_ctx
        .inner()
        .select_local_decryption_key(wrap_set, execution.member_handle.as_str())?;
    Ok(SelectedDecryptionKeyExpiry {
        warning: selected
            .info()
            .key_expiry
            .enforce_expired_usage(allow_expired_key)?,
        key_identity: selected.info().key_identity.clone(),
    })
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
                     (member handle is derived from KAPSARO_PRIVATE_KEY)"
                .to_string(),
        ));
    }
    Ok(())
}

fn enforce_env_kid_absent(explicit_kid: Option<&str>) -> Result<()> {
    if explicit_kid.is_some() {
        return Err(Error::build_invalid_argument_error(
            "--kid cannot be used in environment variable key mode \
                     (kid is derived from KAPSARO_PRIVATE_KEY)"
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
