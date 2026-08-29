// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Command execution context resolution and fixed local-state capabilities.
//! Retains resolved identities for all retries within one command invocation.

use crate::api::key::KeyContext;
use crate::api::kv::KvEncArtifact;
use crate::api::trust::{CurrentMemberSnapshot, TrustPolicyEvaluator};
use crate::app::context::crypto::{
    load_crypto_context_from_env, load_crypto_context_with_selected_kid,
};
use crate::app::context::member::{resolve_command_member, CommandMemberResolution};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::CommandPathResolution;
use crate::app::context::ssh::{resolve_ssh_context_for_resolved_member, SshSigningKeyResolution};
use crate::app::trust::store::load_verified_local_trust_store;
use crate::feature::context::crypto::LocalKeyIdentity;
use crate::feature::context::env_key::is_env_key_mode;
use crate::feature::envelope::wrap_set::WrapSet;
use crate::io::keystore::access::{build_local_keystore_capability_error, KeystoreAccess};
use crate::io::trust::paths::TRUST_DIR_NAME;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::io::workspace::setup::SECRETS_DIR_NAME;
use crate::model::identity::MemberHandle;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{
    ensure_child_dir_restricted_at, open_child_dir, open_optional_child_dir, DirectoryScope,
    OpenDir,
};
use crate::{Error, Result};
#[cfg(any(test, feature = "cli-test-support"))]
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tracing::debug;

/// Fully resolved command execution context.
pub struct ExecutionContext {
    pub member_handle: MemberHandle,
    pub key_ctx: KeyContext,
    pub workspace_root: Option<WorkspaceRoot>,
    workspace: Option<AnchoredDir>,
    secrets_dir: OnceLock<Arc<OpenDir>>,
    home: Option<AnchoredDir>,
    trust_dir: OnceLock<Arc<OpenDir>>,
}

pub(crate) struct SelectedDecryptionKeyExpiry {
    pub(crate) warning: Option<String>,
    pub(crate) key_identity: LocalKeyIdentity,
}

impl ExecutionContext {
    /// Build the context on a member the caller already resolved.
    ///
    /// The SSH signing context is chosen from this same resolution, so taking
    /// it back rather than resolving again keeps the key the command signs with
    /// and the key its SSH context was chosen for the same one.
    fn load_with_resolved_member(
        resolved: CommandMemberResolution,
        selected_kid_override: bool,
        ssh_key: SshSigningKeyResolution,
    ) -> Result<Self> {
        debug!("[CTX] execution mode=ssh-backed");
        let workspace_root = resolved.paths.workspace_root.clone();
        let home = resolved.keystore_access.home().cloned();
        let key_ctx = load_crypto_context_with_selected_kid(
            resolved.keystore_access,
            resolved.member_handle.clone(),
            ssh_key.context.backend,
            ssh_key.context.public_key,
            ssh_key.kid,
            selected_kid_override,
            workspace_root.as_ref().map(|w| w.root_path.clone()),
        )?;

        let workspace = open_optional_workspace_root(workspace_root.as_ref())?;
        Ok(Self {
            member_handle: resolved.member_handle,
            key_ctx: KeyContext::from_inner(key_ctx),
            workspace_root,
            workspace,
            secrets_dir: OnceLock::new(),
            home,
            trust_dir: OnceLock::new(),
        })
    }

    /// Load execution context from environment variables (CI mode).
    pub fn load_from_env(options: &CommonCommandOptions) -> Result<Self> {
        debug!("[CTX] execution mode=env-key");
        let resolved = CommandPathResolution::require_workspace(
            options,
            "environment variable key loading (CI mode)",
        )?;
        let home = resolved.home().cloned();
        let workspace_root = resolved.into_required_workspace_root();
        let key_ctx = load_crypto_context_from_env(workspace_root.root_path.clone())?;
        let member_handle = key_ctx.member_handle_id().clone();

        let workspace = open_optional_workspace_root(Some(&workspace_root))?;
        Ok(Self {
            member_handle,
            key_ctx: KeyContext::from_inner(key_ctx),
            workspace_root: Some(workspace_root),
            workspace,
            secrets_dir: OnceLock::new(),
            home,
            trust_dir: OnceLock::new(),
        })
    }

    /// Open the local trust directory once and reuse that identity.
    ///
    /// Only a directory that exists is remembered: caching its absence would
    /// outlive a trust store created later in the same command.
    pub(crate) fn opened_trust_directory(&self) -> Result<Option<&Arc<OpenDir>>> {
        if let Some(trust_dir) = self.trust_dir.get() {
            return Ok(Some(trust_dir));
        }
        let Some(home) = self.optional_local_state_home() else {
            return Ok(None);
        };
        let Some(opened) = open_optional_child_dir(home, TRUST_DIR_NAME)? else {
            return Ok(None);
        };
        let _ = self.trust_dir.set(Arc::new(opened));
        Ok(self.trust_dir.get())
    }

    /// Open the local trust directory, creating it when it is not there yet,
    /// and keep that identity for the rest of the command.
    ///
    /// The identity that wins the race is the one the whole command keeps, so
    /// the directory just created is offered to the cell and whatever the cell
    /// holds afterwards is what is handed back.
    pub(crate) fn ensured_trust_directory(&self) -> Result<&Arc<OpenDir>> {
        if let Some(trust_dir) = self.trust_dir.get() {
            return Ok(trust_dir);
        }
        let home = self.fixed_local_state_home()?;
        let created = ensure_child_dir_restricted_at(home, TRUST_DIR_NAME)?;
        Ok(self.trust_dir.get_or_init(|| Arc::new(created)))
    }

    /// Workspace root this command bound to a descriptor, if it resolved one.
    pub(crate) fn fixed_workspace_directory(&self) -> Result<&AnchoredDir> {
        self.workspace.as_ref().ok_or_else(|| {
            Error::build_invalid_operation_error(
                "Command requires a resolved workspace".to_string(),
            )
        })
    }

    /// Open the workspace secrets directory once and keep that identity.
    ///
    /// Every write to an artifact runs against this descriptor, so the tree a
    /// command started in is the tree it finishes in even if the workspace path
    /// is repointed while it runs. The identity that wins the race is the one
    /// the whole command keeps, so the directory just opened is offered to the
    /// cell and whatever the cell holds afterwards is what is handed back.
    pub(crate) fn ensured_secrets_directory(&self) -> Result<&Arc<OpenDir>> {
        if let Some(secrets_dir) = self.secrets_dir.get() {
            return Ok(secrets_dir);
        }
        let opened = open_child_dir(self.fixed_workspace_directory()?, SECRETS_DIR_NAME)?;
        Ok(self.secrets_dir.get_or_init(|| Arc::new(opened)))
    }

    /// Re-read one KV artifact through the secrets directory this command fixed.
    ///
    /// The first read named the artifact by a path resolved from configuration,
    /// and the trust gate now answers from the workspace this context bound to.
    /// Reading it again by that path would let a workspace repointed in between
    /// hand the decryption a document the review never saw, so the second read
    /// addresses the directory rather than the path.
    pub fn reload_fixed_kv_artifact(&self, file_name: &str) -> Result<KvEncArtifact> {
        KvEncArtifact::load_at(self.ensured_secrets_directory()?.as_ref(), file_name)
    }

    /// Local state root this command fixed, if it resolved one at all.
    /// A run without local state has no trust store and no keystore to read.
    pub(crate) fn optional_local_state_home(&self) -> Option<&AnchoredDir> {
        self.home.as_ref()
    }

    pub(crate) fn fixed_local_state_home(&self) -> Result<&AnchoredDir> {
        self.home.as_ref().ok_or_else(|| {
            Error::build_invalid_operation_error(
                "Command requires a fixed local-state home".to_string(),
            )
        })
    }

    /// Keystore capability required by commands that cannot run without one.
    /// `subject` names the operation so the operator sees what needs the key.
    pub(crate) fn require_local_keystore_access(&self, subject: &str) -> Result<&KeystoreAccess> {
        self.key_ctx
            .inner()
            .local_keystore_access()
            .ok_or_else(|| build_local_keystore_capability_error(subject))
    }

    #[cfg(any(test, feature = "cli-test-support"))]
    pub fn from_test_parts(
        member_handle: MemberHandle,
        key_ctx: KeyContext,
        workspace_root: Option<WorkspaceRoot>,
        home: Option<PathBuf>,
    ) -> Result<Self> {
        let workspace = open_optional_workspace_root(workspace_root.as_ref())?;
        Ok(Self {
            member_handle,
            key_ctx,
            workspace_root,
            workspace,
            secrets_dir: OnceLock::new(),
            home: home
                .map(|path| {
                    AnchoredDir::open(path, DirectoryScope::LocalState, "test local state root")
                })
                .transpose()?,
            trust_dir: OnceLock::new(),
        })
    }
}

pub fn resolve_read_execution(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    explicit_kid: Option<&str>,
) -> Result<ExecutionContext> {
    resolve_execution(options, member_handle, explicit_kid)
}

pub fn resolve_write_execution(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<ExecutionContext> {
    resolve_execution(options, member_handle, None)
}

/// Resolve the member once and build everything downstream on that resolution.
///
/// Choosing the SSH key and loading the signing key are two reads of the same
/// member. Resolving separately for each would open the local state root twice
/// and let a rotation land in between, leaving the command signing with a key
/// its SSH context was never chosen for. The key the caller named travels to
/// both for the same reason: the SSH identity has to be the one that protects
/// the key the loader unlocks, not the one that protects whichever key is
/// active. Environment key mode never resolves a member at all, so the branch
/// is taken before any of that.
fn resolve_execution(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    explicit_kid: Option<&str>,
) -> Result<ExecutionContext> {
    if is_env_key_mode() {
        debug!("[CTX] environment variable key mode active, skipping SSH resolution");
        return resolve_env_execution(options, member_handle, explicit_kid);
    }
    let resolved = resolve_command_member(options, member_handle)?;
    let ssh_key = resolve_ssh_context_for_resolved_member(options, &resolved, explicit_kid)?;
    run_post_ssh_key_resolution_hook();
    ExecutionContext::load_with_resolved_member(resolved, explicit_kid.is_some(), ssh_key)
}

#[cfg(test)]
thread_local! {
    static POST_SSH_KEY_RESOLUTION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_post_ssh_key_resolution_hook() {
    POST_SSH_KEY_RESOLUTION_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_post_ssh_key_resolution_hook() {}

#[cfg(test)]
pub(crate) fn set_post_ssh_key_resolution_hook(hook: impl FnOnce() + 'static) {
    POST_SSH_KEY_RESOLUTION_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

/// Build the trust gate one read runs under, from the trees this command fixed.
///
/// The member set decides who counts as a member, so it is read through the
/// workspace descriptor the command bound to rather than through the configured
/// path: resolving that path again would let a workspace repointed mid-command
/// answer the authorization question from another tree. The trust store is read
/// through the trust directory this command already opened, for the same reason.
///
/// A run without a local state home has no store to consult, which leaves the
/// evaluator with no store and every key needing review.
pub fn resolve_read_trust_evaluator(execution: &ExecutionContext) -> Result<TrustPolicyEvaluator> {
    let workspace = execution.fixed_workspace_directory().map_err(|_| {
        Error::build_invalid_operation_error(
            "Workspace is required for read trust evaluation".to_string(),
        )
    })?;
    let members = CurrentMemberSnapshot::load_at(workspace)?;
    let keystore = execution.key_ctx.inner().local_keystore_access();
    let Some(home) = execution.optional_local_state_home() else {
        return Ok(TrustPolicyEvaluator::new(members, None));
    };
    let trust_dir = execution.opened_trust_directory()?;
    let store = load_verified_local_trust_store(
        home,
        trust_dir.map(Arc::as_ref),
        execution.member_handle.clone(),
        keystore,
    )?
    .map(|loaded| loaded.into_store());
    Ok(TrustPolicyEvaluator::new(members, store))
}

/// Bind a resolved workspace root to a descriptor.
///
/// A run without a workspace has no tree to open, which several commands are
/// built for rather than a failure.
fn open_optional_workspace_root(
    workspace_root: Option<&WorkspaceRoot>,
) -> Result<Option<AnchoredDir>> {
    workspace_root
        .map(|workspace| {
            AnchoredDir::open(
                workspace.root_path.clone(),
                DirectoryScope::Generic,
                "workspace root",
            )
        })
        .transpose()
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
