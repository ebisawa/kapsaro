// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local keystore facade.

use std::path::{Path, PathBuf};

use crate::feature::context::crypto::{load_crypto_context_from_keystore, CryptoContext};
use crate::feature::context::expiry::enforce_expired_key_usage;
use crate::feature::envelope::wrap_set::WrapSet;
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::io::keystore::active::{load_active_kid, set_active_kid};
use crate::io::keystore::storage::{list_kids, list_member_handles, load_public_key};
use crate::model::common::WrapItem;
use crate::model::public_key::{PublicKey, VerifiedRecipientKey};
use crate::Result;

use super::operation::OperationOptions;
use super::ssh::{into_internal_backend, SshSignatureBackend};

/// Filesystem-backed local keystore.
#[derive(Debug, Clone)]
pub struct LocalKeyStore {
    root: PathBuf,
}

/// Loaded local key context for signing and decrypting artifacts.
pub struct KeyContext {
    inner: CryptoContext,
}

/// Inputs required to load and decrypt a local key context.
pub struct KeyContextOptions {
    member_handle: String,
    kid: Option<String>,
    ssh_backend: Box<dyn SshSignatureBackend>,
    ssh_pubkey: String,
    workspace_path: Option<PathBuf>,
    operation_options: OperationOptions,
}

/// Verified recipient keys in caller-chosen order.
#[derive(Debug, Clone)]
pub struct RecipientKeys {
    handles: Vec<String>,
    keys: Vec<VerifiedRecipientKey>,
}

impl LocalKeyStore {
    /// Build a keystore facade from an explicit `keys` directory path.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Return the keystore root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// List member handles stored in the local keystore.
    pub fn list_members(&self) -> Result<Vec<String>> {
        list_member_handles(&self.root)
    }

    /// List key IDs stored for a member.
    pub fn list_kids(&self, member_handle: &str) -> Result<Vec<String>> {
        list_kids(&self.root, member_handle)
    }

    /// Load the active key ID for a member.
    pub fn load_active_kid(&self, member_handle: &str) -> Result<Option<String>> {
        load_active_kid(member_handle, &self.root)
    }

    /// Set the active key ID for a member.
    pub fn set_active_kid(&self, member_handle: &str, kid: &str) -> Result<()> {
        set_active_kid(member_handle, kid, &self.root)
    }

    /// Load and decrypt a local key context using a caller-supplied SSH backend.
    pub fn load_key_context(&self, options: KeyContextOptions) -> Result<KeyContext> {
        load_crypto_context_from_keystore(
            self.root.clone(),
            &options.member_handle,
            options.kid.as_deref(),
            into_internal_backend(options.ssh_backend),
            options.ssh_pubkey,
            options.workspace_path,
            options.operation_options.debug(),
        )
        .map(KeyContext::from_inner)
    }

    /// Load and verify recipient public keys.
    pub fn load_recipient_keys<I, S>(
        &self,
        recipients: I,
        options: OperationOptions,
    ) -> Result<RecipientKeys>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let recipients = recipients.into_iter().map(Into::into).collect::<Vec<_>>();
        let public_keys = recipients
            .iter()
            .map(|handle| {
                let kid = crate::io::keystore::helpers::resolve_kid(&self.root, handle, None)?;
                load_public_key(&self.root, handle, &kid)
            })
            .collect::<Result<Vec<_>>>()?;
        RecipientKeys::verify(recipients, &public_keys, options)
    }
}

impl KeyContextOptions {
    /// Build key context loading options from required SSH inputs.
    pub fn new(
        member_handle: impl Into<String>,
        ssh_backend: Box<dyn SshSignatureBackend>,
        ssh_pubkey: impl Into<String>,
    ) -> Self {
        Self {
            member_handle: member_handle.into(),
            kid: None,
            ssh_backend,
            ssh_pubkey: ssh_pubkey.into(),
            workspace_path: None,
            operation_options: OperationOptions::default(),
        }
    }

    /// Set an explicit key ID.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Set an optional workspace path used by key protection checks.
    pub fn with_workspace_path(mut self, workspace_path: impl Into<PathBuf>) -> Self {
        self.workspace_path = Some(workspace_path.into());
        self
    }

    /// Set shared operation options for underlying verification.
    pub fn with_operation_options(mut self, options: OperationOptions) -> Self {
        self.operation_options = options;
        self
    }
}

impl KeyContext {
    pub(crate) fn from_inner(inner: CryptoContext) -> Self {
        Self { inner }
    }

    pub(crate) fn inner(&self) -> &CryptoContext {
        &self.inner
    }

    pub(crate) fn keystore_root(&self) -> Option<&Path> {
        self.inner.local_keystore_root()
    }

    pub(crate) fn enforce_decryption_key_not_expired(
        &self,
        wrap_items: &[WrapItem],
        options: OperationOptions,
    ) -> Result<()> {
        let wrap_set = WrapSet::parse(wrap_items, "Document")?;
        let selected = self.inner().select_local_decryption_key(
            &wrap_set,
            self.member_handle(),
            options.debug(),
        )?;
        let _ = enforce_expired_key_usage(
            &selected.info().expires_at,
            options.allow_expired_key(),
            "Private key",
        )?;
        Ok(())
    }

    /// Return the loaded member handle.
    pub fn member_handle(&self) -> &str {
        self.inner.member_handle()
    }

    /// Return the loaded key ID.
    pub fn kid(&self) -> &str {
        self.inner.kid()
    }

    /// Return the verified key expiration timestamp.
    pub fn expires_at(&self) -> &str {
        self.inner.expires_at()
    }
}

impl RecipientKeys {
    fn verify(
        handles: Vec<String>,
        public_keys: &[PublicKey],
        options: OperationOptions,
    ) -> Result<Self> {
        validate_recipient_key_subjects(&handles, public_keys)?;
        let keys = verify_recipient_public_keys(public_keys, options.debug())?;
        Ok(Self { handles, keys })
    }

    pub(crate) fn handles(&self) -> &[String] {
        &self.handles
    }

    pub(crate) fn keys(&self) -> &[VerifiedRecipientKey] {
        &self.keys
    }
}

fn validate_recipient_key_subjects(handles: &[String], public_keys: &[PublicKey]) -> Result<()> {
    if handles.len() != public_keys.len() {
        return Err(crate::Error::build_invalid_argument_error(format!(
            "recipient handle count ({}) does not match public key count ({})",
            handles.len(),
            public_keys.len()
        )));
    }
    for (handle, public_key) in handles.iter().zip(public_keys.iter()) {
        if public_key.protected.subject_handle != *handle {
            return Err(crate::Error::build_invalid_argument_error(format!(
                "recipient handle '{}' does not match public key subject_handle '{}'",
                handle, public_key.protected.subject_handle
            )));
        }
    }
    Ok(())
}
