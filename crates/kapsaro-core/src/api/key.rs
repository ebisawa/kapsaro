// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local keystore facade.

use std::path::{Path, PathBuf};

use crate::feature::context::crypto::{load_crypto_context_from_keystore, CryptoContext};
use crate::feature::context::expiry::enforce_expired_key_usage;
use crate::feature::envelope::wrap_set::WrapSet;
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::io::keystore::access::KeystoreAccess;
use crate::model::common::WrapItem;
use crate::model::public_key::{PublicKey, VerifiedRecipientKey};
use crate::Result;

pub use crate::model::identity::{Kid, MemberHandle};

use super::operation::OperationOptions;
use super::ssh::{into_internal_backend, SshSignatureBackend};

/// Filesystem-backed local keystore.
#[derive(Clone)]
pub struct LocalKeyStore {
    access: KeystoreAccess,
}

impl std::fmt::Debug for LocalKeyStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalKeyStore")
            .finish_non_exhaustive()
    }
}

/// Loaded local key context for signing and decrypting artifacts.
pub struct KeyContext {
    inner: CryptoContext,
}

/// Inputs required to load and decrypt a local key context.
pub struct KeyContextOptions {
    member_handle: MemberHandle,
    kid: Option<Kid>,
    ssh_backend: Box<dyn SshSignatureBackend>,
    ssh_pubkey: String,
    workspace_path: Option<PathBuf>,
}

/// Verified recipient keys in caller-chosen order.
#[derive(Debug, Clone)]
pub struct RecipientKeys {
    handles: Vec<String>,
    keys: Vec<VerifiedRecipientKey>,
}

impl LocalKeyStore {
    /// Open an existing keystore from an explicit `keys` directory path.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        KeystoreAccess::open(root).map(|access| Self { access })
    }

    /// Create or reuse a restricted keystore directory.
    pub fn create(root: impl Into<PathBuf>) -> Result<Self> {
        KeystoreAccess::create(root).map(|access| Self { access })
    }

    /// Return the keystore root directory.
    pub fn root(&self) -> &Path {
        self.access.root()
    }

    /// List member handles stored in the local keystore.
    pub fn list_members(&self) -> Result<Vec<MemberHandle>> {
        self.access.list_members()
    }

    /// List key IDs stored for a member.
    pub fn list_kids(&self, member_handle: &MemberHandle) -> Result<Vec<Kid>> {
        self.access.list_kids(member_handle)
    }

    /// Load the active key ID for a member.
    pub fn load_active_kid(&self, member_handle: &MemberHandle) -> Result<Option<Kid>> {
        self.access.load_active_kid(member_handle)
    }

    /// Set the active key ID for a member.
    ///
    /// The key has to already be in the keystore. Pointing the marker at a key
    /// that is not there would leave the member unusable, and naming an absent
    /// member would create a directory holding no key at all, which makes the
    /// keystore look like it has two members and stops the handle from being
    /// resolved automatically.
    pub fn set_active_kid(&self, member_handle: &MemberHandle, kid: &Kid) -> Result<()> {
        self.access.activate_existing_key(member_handle, kid)
    }

    /// Load and decrypt a local key context using a caller-supplied SSH backend.
    pub fn load_key_context(&self, options: KeyContextOptions) -> Result<KeyContext> {
        load_crypto_context_from_keystore(
            self.access.clone(),
            options.member_handle,
            options.kid.as_ref().map(Kid::as_str),
            into_internal_backend(options.ssh_backend),
            options.ssh_pubkey,
            options.workspace_path,
        )
        .map(KeyContext::from_inner)
    }

    /// Load and verify recipient public keys.
    pub fn load_recipient_keys<I>(&self, recipients: I) -> Result<RecipientKeys>
    where
        I: IntoIterator<Item = MemberHandle>,
    {
        let recipients = recipients.into_iter().collect::<Vec<_>>();
        let public_keys = recipients
            .iter()
            .map(|handle| {
                self.access
                    .resolve_public_key(handle, None)
                    .map(|(_, public_key)| public_key)
            })
            .collect::<Result<Vec<_>>>()?;
        let handles = recipients
            .into_iter()
            .map(MemberHandle::into_string)
            .collect();
        RecipientKeys::verify(handles, &public_keys)
    }

    pub(crate) fn access(&self) -> &KeystoreAccess {
        &self.access
    }
}

impl KeyContextOptions {
    /// Build key context loading options from required SSH inputs.
    pub fn new(
        member_handle: MemberHandle,
        ssh_backend: Box<dyn SshSignatureBackend>,
        ssh_pubkey: impl Into<String>,
    ) -> Self {
        Self {
            member_handle,
            kid: None,
            ssh_backend,
            ssh_pubkey: ssh_pubkey.into(),
            workspace_path: None,
        }
    }

    /// Set an explicit key ID.
    pub fn with_kid(mut self, kid: Kid) -> Self {
        self.kid = Some(kid);
        self
    }

    /// Set an optional workspace path used by key protection checks.
    pub fn with_workspace_path(mut self, workspace_path: impl Into<PathBuf>) -> Self {
        self.workspace_path = Some(workspace_path.into());
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

    pub(crate) fn enforce_decryption_key_not_expired(
        &self,
        wrap_items: &[WrapItem],
        options: OperationOptions,
    ) -> Result<()> {
        let wrap_set = WrapSet::parse(wrap_items, "Document")?;
        let selected = self
            .inner()
            .select_local_decryption_key(&wrap_set, self.member_handle())?;
        let _ = enforce_expired_key_usage(
            &selected.info().expires_at,
            options.allow_expired_key(),
            "Private key",
        )?;
        Ok(())
    }

    /// Return the loaded member handle.
    pub fn member_handle(&self) -> &MemberHandle {
        self.inner.member_handle_id()
    }

    /// Return the loaded key ID.
    pub fn kid(&self) -> &Kid {
        self.inner.kid_id()
    }

    /// Return the verified key expiration timestamp.
    pub fn expires_at(&self) -> &str {
        self.inner.expires_at()
    }
}

impl RecipientKeys {
    fn verify(handles: Vec<String>, public_keys: &[PublicKey]) -> Result<Self> {
        validate_recipient_key_subjects(&handles, public_keys)?;
        let keys = verify_recipient_public_keys(public_keys)?;
        Ok(Self { handles, keys })
    }

    pub(crate) fn handles(&self) -> &[String] {
        &self.handles
    }

    pub(crate) fn keys(&self) -> &[VerifiedRecipientKey] {
        &self.keys
    }

    pub(crate) fn from_verified_parts(
        handles: Vec<String>,
        keys: Vec<VerifiedRecipientKey>,
    ) -> Result<Self> {
        let public_keys = keys
            .iter()
            .map(|key| key.document().clone())
            .collect::<Vec<_>>();
        validate_recipient_key_subjects(&handles, &public_keys)?;
        Ok(Self { handles, keys })
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
