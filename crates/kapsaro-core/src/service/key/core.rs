// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Core local keystore operations and capability types.

use std::path::{Path, PathBuf};

use crate::feature::context::crypto::{
    build_signing_key, load_crypto_context_from_keystore,
    load_crypto_context_from_keystore_with_selected_kid, CryptoContext,
};
use crate::feature::context::expiry::LocalKeyPairExpiry;
use crate::feature::envelope::wrap_set::WrapSet;
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::public_key_source::WorkspacePublicKeySource;
use crate::model::common::WrapItem;
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm};
use crate::model::public_key::{PublicKey, VerifiedRecipientKey};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::atomic::save_text_restricted;
use crate::support::fs::relative::DirectoryScope;
use crate::Result;

pub use crate::model::identity::{Kid, MemberHandle};

/// Save a password-protected private-key export with owner-only permissions.
pub fn save_private_export_text(path: impl AsRef<std::path::Path>, content: &str) -> Result<()> {
    save_text_restricted(path.as_ref(), content)
}

/// Validate an encoded password-protected key without constructing a context.
pub fn load_environment_key(encoded: SecretString, password: SecretString) -> Result<()> {
    crate::feature::context::env_key::parse_env_key(encoded.into_inner(), password.into_inner())
        .map(|_| ())
}

use crate::service::operation::OperationOptions;
use crate::service::secret::SecretString;
use crate::service::ssh::{
    into_internal_backend, resolve_ssh_signing_context_for_fingerprint, SshSignatureBackend,
    SshSigningContextResolution, SshSigningInputs,
};

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

/// Explicit SSH inputs for loading one key from a fixed local keystore.
pub struct LocalKeyContextRequest {
    member_handle: MemberHandle,
    kid: Option<Kid>,
    workspace_path: Option<PathBuf>,
    ssh: SshSigningInputs,
}

/// Verified recipient keys in caller-chosen order.
#[derive(Debug, Clone)]
pub struct RecipientKeys {
    handles: Vec<String>,
    keys: Vec<VerifiedRecipientKey>,
}

impl LocalKeyStore {
    pub(crate) fn from_access(access: KeystoreAccess) -> Self {
        Self { access }
    }

    /// Open an existing keystore from an explicit `keys` directory path.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        KeystoreAccess::open(root).map(|access| Self { access })
    }

    /// Open an existing keystore through one fixed local-state home.
    pub fn open_home(home: impl Into<PathBuf>, owner: &MemberHandle) -> Result<Self> {
        let home = AnchoredDir::open(home.into(), DirectoryScope::LocalState, "local state root")?;
        KeystoreAccess::open_from_anchored_home_required(&home, owner).map(|access| Self { access })
    }

    /// Open a restricted keystore directory, creating it when it is absent.
    pub fn ensure(root: impl Into<PathBuf>) -> Result<Self> {
        KeystoreAccess::ensure(root).map(|access| Self { access })
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

    /// Load a local key after binding SSH selection to this keystore capability.
    pub fn load_selected_key_context(&self, request: LocalKeyContextRequest) -> Result<KeyContext> {
        let (kid, private_key, _) = self.access.resolve_key_pair(
            &request.member_handle,
            request.kid.as_ref().map(Kid::as_str),
        )?;
        let fingerprint = resolve_ssh_fingerprint(&private_key)?;
        let ssh = resolve_ssh_signing_context_for_fingerprint(&request.ssh, fingerprint, false)?;
        let key_ctx = load_crypto_context_from_keystore_with_selected_kid(
            self.access.clone(),
            request.member_handle,
            kid,
            request.kid.is_some(),
            ssh.backend,
            ssh.public_key,
            request.workspace_path,
        )?;
        Ok(KeyContext::from_inner(key_ctx))
    }

    /// Resolve the SSH context protecting one key through this fixed keystore.
    pub fn resolve_signing_context(
        &self,
        member_handle: MemberHandle,
        kid: Option<Kid>,
        ssh: &SshSigningInputs,
        check_determinism: bool,
    ) -> Result<(Kid, SshSigningContextResolution)> {
        let (selected_kid, private_key, _) = self
            .access
            .resolve_key_pair(&member_handle, kid.as_ref().map(Kid::as_str))?;
        let fingerprint = resolve_ssh_fingerprint(&private_key)?;
        let context =
            resolve_ssh_signing_context_for_fingerprint(ssh, fingerprint, check_determinism)?;
        Ok((selected_kid, context))
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

impl LocalKeyContextRequest {
    /// Build a local key load request from already resolved SSH inputs.
    pub fn new(member_handle: MemberHandle, ssh: SshSigningInputs) -> Self {
        Self {
            member_handle,
            kid: None,
            workspace_path: None,
            ssh,
        }
    }

    /// Bind workspace-backed public-key resolution to one explicit path.
    pub fn with_workspace_path(mut self, workspace_path: impl Into<PathBuf>) -> Self {
        self.workspace_path = Some(workspace_path.into());
        self
    }

    /// Select a specific local key ID.
    pub fn with_kid(mut self, kid: Kid) -> Self {
        self.kid = Some(kid);
        self
    }
}

impl KeyContext {
    /// Load an encoded password-protected key for one explicit workspace.
    pub fn load_environment_key(
        encoded: SecretString,
        password: SecretString,
        workspace_path: PathBuf,
    ) -> Result<Self> {
        let result = crate::feature::context::env_key::parse_env_key(
            encoded.into_inner(),
            password.into_inner(),
        )?;
        build_environment_crypto_context(result, workspace_path).map(Self::from_inner)
    }

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
    ) -> Result<Option<String>> {
        let wrap_set = WrapSet::parse(wrap_items, "Document")?;
        let selected = self
            .inner()
            .select_local_decryption_key(&wrap_set, self.member_handle())?;
        selected
            .info()
            .key_expiry
            .enforce_expired_usage(options.allow_expired_key())
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

fn resolve_ssh_fingerprint(private_key: &PrivateKey) -> Result<&str> {
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, .. } => Ok(fpr),
        _ => Err(crate::Error::build_crypto_error(
            "Expected SshSig algorithm for SSH signing context".to_string(),
        )),
    }
}

fn build_environment_crypto_context(
    result: crate::feature::context::env_key::EnvKeyParseResult,
    workspace_path: PathBuf,
) -> Result<CryptoContext> {
    let kid = Kid::try_from(result.verified_key.proof().kid().to_string())?;
    let signing_key = build_signing_key(result.verified_key.document())?;
    let context = CryptoContext::new(
        result.member_handle,
        kid,
        Box::new(WorkspacePublicKeySource::new(workspace_path.clone())),
        Some(workspace_path),
        result.verified_key,
        signing_key,
        LocalKeyPairExpiry::from_private_key(result.expires_at),
    );
    Ok(context.with_local_key_access(None, None))
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
