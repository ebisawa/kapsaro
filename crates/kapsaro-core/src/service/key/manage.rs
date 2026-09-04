// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Service-layer orchestration for local key management operations.
//! Resolves keystore paths and key I/O around the caller-supplied inputs before feature calls.

use std::path::Path;

use crate::feature::key::material::verify_private_key_material;
use crate::feature::key::portable_export::{
    build_password_strength_warning, export_private_key_portable, validate_export_password,
    ExportPasswordPolicy, PortableExportOptions, PortableExportOutput,
};
use crate::feature::key::protection::encryption::decrypt_private_key;
use crate::feature::verify::private_key::verify_private_key_matches_public_key;
use crate::feature::verify::public_key::{
    verify_public_key_with_attestation_context, KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT,
};
use crate::io::keystore::access::{KeystoreAccess, PublicKeySnapshotEntry};
use crate::io::keystore::helpers::{find_member_by_kid, resolve_member_kid_query};
use crate::io::keystore::member::load_single_member_handle_from_keystore;
use crate::io::ssh::backend::SignatureBackend;
use crate::io::trust::paths::TRUST_DIR_NAME;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::private_key::PrivateKeyPlaintext;
use crate::service::key::build_no_active_key_error;
use crate::service::key::export::save_exported_public_key;
use crate::service::key::trust_signer::{
    apply_trust_signer_removal, resolve_trust_signer_removal, TrustSignerRemovalOutcome,
    TrustSignerRemovalRequest,
};
use crate::service::key::types::{
    KeyActivateResult, KeyExportPrivateResult, KeyExportResult, KeyInfo, KeyListResult,
    KeyRemoveResult, MissingKeyDocument,
};
use crate::service::keystore::open_local_keystore;
use crate::service::ssh::SshSigningContextResolution;
use crate::service::trust::store::{
    load_stored_trust_signer, LocalStateBinding, TrustSignerRecord,
};
use crate::service::trust::TrustCommandSession;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_optional_child_dir, OpenDir};
use crate::support::secret::SecretString;
use crate::{Error, Result};

fn resolve_required_member_with_access(
    access: &KeystoreAccess,
    member_handle: Option<String>,
) -> Result<MemberHandle> {
    resolve_member_with_access(access, member_handle)?.ok_or_else(|| {
        crate::service::key::build_missing_member_handle_error(
            "A member handle is required for this operation",
        )
    })
}

fn resolve_key_owner_with_access(
    access: &KeystoreAccess,
    member_handle: Option<String>,
    kid: &str,
) -> Result<MemberHandle> {
    match resolve_member_with_access(access, member_handle)? {
        Some(member_handle) => Ok(member_handle),
        None => find_member_by_kid(access, kid),
    }
}

fn resolve_member_with_access(
    access: &KeystoreAccess,
    member_handle: Option<String>,
) -> Result<Option<MemberHandle>> {
    match member_handle {
        Some(member_handle) => MemberHandle::try_from(member_handle).map(Some),
        None => load_single_member_handle_from_keystore(access),
    }
}

/// Directories one local key command works through.
///
/// The local state home is opened once and the keystore and the trust directory
/// are opened from it, so every step addresses the directories this command
/// resolved rather than whatever the same paths name later. What the directory
/// handles fix is which directory is read and written; they say nothing about
/// the contents staying still, so a step whose decision depends on the stored
/// content re-reads it rather than trusting an earlier read.
pub(super) struct KeyCommandCapabilities {
    home: AnchoredDir,
    keystore: KeystoreAccess,
    trust_dir: Option<OpenDir>,
}

impl KeyCommandCapabilities {
    /// Open the local state home and everything a key command reaches under it.
    ///
    /// The trust directory is opened from the home the keystore is bound to, so
    /// both capabilities describe the same local state root for the whole
    /// command even if the paths that reached it are repointed afterwards.
    pub(super) fn open(base_dir: &Path) -> Result<Self> {
        let keystore = open_local_keystore(base_dir)?;
        let home = keystore
            .home()
            .cloned()
            .ok_or_else(build_unbound_keystore_error)?;
        let trust_dir = open_optional_child_dir(&home, TRUST_DIR_NAME)?;
        Ok(Self {
            home,
            keystore,
            trust_dir,
        })
    }

    pub(super) fn keystore(&self) -> &KeystoreAccess {
        &self.keystore
    }

    /// The local state this command opened, for a step that resolves its own.
    ///
    /// The trust store hand-over resolves a signing identity from the configured
    /// path, which is a second chance to reach a directory. Handing it what was
    /// opened here lets it refuse a re-signing that would land elsewhere.
    pub(super) fn local_state_binding(&self) -> LocalStateBinding<'_> {
        LocalStateBinding::new(&self.home, &self.keystore, self.trust_dir.as_ref())
    }

    /// Read which key the stored trust store signature names.
    ///
    /// The keystore this command opened is handed over rather than left to be
    /// resolved again, so the signature is verified against the keys the
    /// removal was decided against even if `keys` is replaced meanwhile.
    pub(super) fn stored_trust_signer(&self, owner: &MemberHandle) -> TrustSignerRecord {
        load_stored_trust_signer(
            &self.home,
            self.trust_dir.as_ref(),
            owner,
            Some(self.keystore()),
        )
    }
}

pub fn list_keys_command(base_dir: &Path, member_handle: Option<String>) -> Result<KeyListResult> {
    // Listing asks what the local state root holds, and a root without a
    // keystore holds nothing. The other key commands act on a key and still
    // refuse when there is none to act on.
    let Some(access) = KeystoreAccess::open_optional_from_home(base_dir)? else {
        return Ok(KeyListResult {
            entries: Vec::new(),
            total_keys: 0,
        });
    };
    let member_handles = resolve_member_handles(&access, member_handle)?;
    let entries = load_key_infos(&access, &member_handles)?;
    let total_keys = entries.iter().map(|(_, keys)| keys.len()).sum();

    Ok(KeyListResult {
        entries,
        total_keys,
    })
}

pub fn activate_key_command(
    base_dir: &Path,
    member_handle: Option<String>,
    kid: Option<String>,
) -> Result<KeyActivateResult> {
    let capabilities = KeyCommandCapabilities::open(base_dir)?;
    let access = capabilities.keystore();
    let member_handle = resolve_required_member_with_access(access, member_handle)?;
    run_post_member_resolution_hook();
    let kid = activate_requested_kid(access, &member_handle, kid)?;
    // Read-only, and after the write: activation itself never signs, so the
    // operator learns the trust store still leans on another key without this
    // command needing an SSH signing context.
    let stored_signer = capabilities.stored_trust_signer(&member_handle);
    let report = TrustSignerReport::from(stored_signer);
    Ok(KeyActivateResult {
        member_handle: member_handle.into_string(),
        kid: kid.into_string(),
        trust_store_signer_kid: report.signer_kid,
        trust_store_warning: report.warning,
    })
}

/// What a read-only activation can say about the stored local trust store.
///
/// Activation changes no signature, so it only reports what the stored document
/// already says. A store that is absent names no key and there is nothing to
/// act on. A store that would not verify also names no key, but that is a
/// finding of its own: the approvals it holds are unusable until it is
/// repaired, and reporting nothing would let the activation look complete while
/// the trust state it reports on cannot be read at all.
struct TrustSignerReport {
    signer_kid: Option<String>,
    warning: Option<String>,
}

impl From<TrustSignerRecord> for TrustSignerReport {
    fn from(signer: TrustSignerRecord) -> Self {
        match signer {
            TrustSignerRecord::Signer(kid) => Self {
                signer_kid: Some(kid),
                warning: None,
            },
            TrustSignerRecord::Absent => Self {
                signer_kid: None,
                warning: None,
            },
            TrustSignerRecord::Unreadable(error) => Self {
                signer_kid: None,
                warning: Some(build_unreadable_trust_store_warning(&error)),
            },
        }
    }
}

fn build_unreadable_trust_store_warning(error: &Error) -> String {
    format!(
        "The local trust store could not be read, so the key it depends on is unknown: {}",
        error.format_user_message()
    )
}

/// Remove one local key, keeping the local trust store verifiable.
///
/// `resolve_signing_execution` is only called when the removal would take the
/// store's signer away, so a command that removes an unrelated key never has to
/// resolve an SSH signing context. It supplies the signing identity alone: the
/// hand-over runs inside the guard, which is what decides the removal may go on.
///
/// A removal the keystore would refuse is asked about before the hand-over
/// re-signs the trust store, so the ordinary refusal costs no signature move.
/// The two answers are read under separate lock acquisitions, though, and a
/// concurrent `key activate` landing between them can still make the second one
/// a refusal after the re-signing has been committed. That residual window is
/// accepted rather than closed: what it leaves behind is a trust store signed by
/// a key the keystore still holds, so the stored approvals keep verifying, and
/// re-running `key remove` finishes the removal from there. An I/O failure met
/// by the deletion itself cannot be asked about in advance and ends the same
/// way: the failure names the key that took the signature over, so the state
/// the run left behind is readable from what it reported.
pub fn remove_key_command<Resign>(
    base_dir: &Path,
    member_handle: Option<String>,
    kid: String,
    force: bool,
    resolve_signing_execution: Resign,
) -> Result<KeyRemoveResult>
where
    Resign: FnOnce(&MemberHandle) -> Result<TrustCommandSession>,
{
    let capabilities = KeyCommandCapabilities::open(base_dir)?;
    let access = capabilities.keystore();
    let member_handle = resolve_key_owner_with_access(access, member_handle, &kid)?;
    run_post_member_resolution_hook();
    let kid = resolve_member_kid_query(access, &member_handle, &kid)?;
    let request = TrustSignerRemovalRequest {
        member_handle: &member_handle,
        kid: &kid,
        force,
    };
    let removal = resolve_trust_signer_removal(&capabilities, &request)?;
    // The advance check is only worth anything while it decides exactly what the
    // deletion decides, so both phases are handed the same validation.
    let validate = |was_active| validate_key_removal(&member_handle, &kid, was_active, force);
    if removal.writes_to_trust_store() {
        access.ensure_key_removable(&member_handle, &kid, validate)?;
    }
    let outcome =
        apply_trust_signer_removal(&capabilities, removal, &request, resolve_signing_execution)?;
    let was_active =
        delete_key_after_signature_handover(access, &member_handle, &kid, validate, &outcome)?;
    Ok(build_key_remove_result(
        member_handle,
        kid,
        was_active,
        outcome,
    ))
}

/// Delete the key, keeping a hand-over that already happened in the failure.
///
/// The hand-over is committed by the time the deletion runs, so a bare deletion
/// failure would leave the operator with a key they think is gone and a member
/// signing the local trust store through a key they were never told about. Both
/// are stated in the failure instead, and the key that could not be deleted is
/// named so the removal can be finished from there.
fn delete_key_after_signature_handover<Validate>(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
    kid: &Kid,
    validate: Validate,
    outcome: &TrustSignerRemovalOutcome,
) -> Result<bool>
where
    Validate: FnOnce(bool) -> Result<()>,
{
    access
        .remove_key_with_validation(member_handle, kid, validate)
        .map_err(|error| match outcome.resigned_trust_store_kid.as_deref() {
            Some(signer_kid) => {
                build_deletion_after_resign_error(member_handle, kid, signer_kid, error)
            }
            None => error,
        })
}

/// Report a deletion that failed once the trust store signature had moved.
///
/// The category, the rule, and the recovery route all decide how the failure is
/// classified further up, so only its message grows here.
fn build_deletion_after_resign_error(
    member_handle: &MemberHandle,
    kid: &Kid,
    signer_kid: &str,
    cause: Error,
) -> Error {
    let message = format!(
        "The local trust store signature was handed to key '{}' and stays there, so the stored \
         approvals verify under it, but key '{}' could not be removed afterwards: {}. Run \
         'kapsaro key remove {} --member-handle {}' again to finish removing the key.",
        signer_kid,
        kid,
        cause.format_user_message(),
        kid,
        member_handle
    );
    cause.with_message(message)
}

fn build_key_remove_result(
    member_handle: MemberHandle,
    kid: Kid,
    was_active: bool,
    outcome: TrustSignerRemovalOutcome,
) -> KeyRemoveResult {
    KeyRemoveResult {
        member_handle: member_handle.into_string(),
        kid: kid.into_string(),
        was_active,
        resigned_trust_store_kid: outcome.resigned_trust_store_kid,
        trust_store_warning: outcome.trust_store_warning,
    }
}

/// Write out the public half of one local key.
///
/// Only the local state root is resolved: the document is read from the
/// keystore and written to the path the caller named, so an export never
/// depends on a workspace being found.
pub fn export_key_command(
    base_dir: &Path,
    member_handle: Option<String>,
    kid: Option<String>,
    out: &Path,
) -> Result<KeyExportResult> {
    let access = open_local_keystore(base_dir)?;
    let member_handle = resolve_required_member_with_access(&access, member_handle)?;
    let kid = resolve_active_kid(&access, &member_handle, kid)?;
    let public_key = access.load_public_key(&member_handle, &kid)?;
    let result = KeyExportResult {
        member_handle: member_handle.into_string(),
        kid: kid.into_string(),
        public_key,
    };
    save_exported_public_key(out, &result.public_key)?;
    Ok(result)
}

pub fn export_private_key_command(
    base_dir: &Path,
    member_handle: String,
    kid: Option<String>,
    password: &crate::service::secret::SecretString,
    allow_weak_password: bool,
    ssh_ctx: SshSigningContextResolution,
) -> Result<KeyExportPrivateResult> {
    let password_policy = export_password_policy(allow_weak_password);
    validate_export_password(password.expose_secret(), password_policy)?;

    let loaded = load_selected_private_key(base_dir, member_handle, kid, &ssh_ctx)?;
    let encoded_key = encode_portable_private_key(&loaded, password.as_inner(), password_policy)?;

    Ok(PortableExportOutput {
        member_handle: loaded.member_handle,
        kid: loaded.kid,
        encoded_key,
        password_warning: build_export_password_warning(
            password.expose_secret(),
            allow_weak_password,
        ),
    }
    .into())
}

/// Load and validate the key material an export re-encrypts.
fn load_selected_private_key(
    base_dir: &Path,
    member_handle: String,
    kid: Option<String>,
    ssh_ctx: &SshSigningContextResolution,
) -> Result<PrivateKeyExportMaterial> {
    let access = open_local_keystore(base_dir)?;
    let member_handle = MemberHandle::try_from(member_handle)?;
    let kid = resolve_active_kid(&access, &member_handle, kid)?;
    load_private_key_export_material(
        &access,
        member_handle,
        kid,
        ssh_ctx.backend.as_ref(),
        &ssh_ctx.public_key,
    )
}

fn encode_portable_private_key(
    loaded: &PrivateKeyExportMaterial,
    password: &SecretString,
    password_policy: ExportPasswordPolicy,
) -> Result<SecretString> {
    export_private_key_portable(
        &loaded.plaintext,
        &loaded.member_handle,
        &loaded.kid,
        &loaded.created_at,
        &loaded.expires_at,
        password,
        PortableExportOptions::new(password_policy),
    )
}

fn export_password_policy(allow_weak_password: bool) -> ExportPasswordPolicy {
    if allow_weak_password {
        ExportPasswordPolicy::AllowWeak
    } else {
        ExportPasswordPolicy::Recommended
    }
}

fn build_export_password_warning(password: &str, allow_weak_password: bool) -> Option<String> {
    allow_weak_password
        .then(|| build_password_strength_warning(password))
        .flatten()
}

struct PrivateKeyExportMaterial {
    plaintext: PrivateKeyPlaintext,
    member_handle: String,
    kid: String,
    created_at: String,
    expires_at: String,
}

// Test-only seam: runs once the owner is resolved so a test can swap the
// keystore path underneath and prove the command stays bound to the directory
// it opened. Compiled out of production builds.
#[cfg(test)]
thread_local! {
    static POST_MEMBER_RESOLUTION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_post_member_resolution_hook() {
    POST_MEMBER_RESOLUTION_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_post_member_resolution_hook() {}

#[cfg(test)]
pub(crate) fn set_post_member_resolution_hook(hook: impl FnOnce() + 'static) {
    POST_MEMBER_RESOLUTION_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

/// Report a keystore that was opened without the root the trust store shares.
fn build_unbound_keystore_error() -> Error {
    Error::build_invalid_operation_error(
        "Key command requires a keystore opened from a local state root".to_string(),
    )
}

fn resolve_member_handles(
    access: &KeystoreAccess,
    member_handle: Option<String>,
) -> Result<Vec<MemberHandle>> {
    match member_handle {
        Some(member_handle) => Ok(vec![MemberHandle::try_from(member_handle)?]),
        None => access.list_members(),
    }
}

fn load_key_infos(
    access: &KeystoreAccess,
    member_handles: &[MemberHandle],
) -> Result<Vec<(String, Vec<KeyInfo>)>> {
    member_handles
        .iter()
        .map(|member_handle| load_member_key_infos(access, member_handle))
        .collect()
}

fn load_member_key_infos(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
) -> Result<(String, Vec<KeyInfo>)> {
    let (active_kid, entries) = access.load_public_key_entries_with_active(member_handle)?;
    let key_infos = entries
        .into_iter()
        .map(|entry| {
            let active = active_kid.as_ref() == Some(entry.kid());
            match entry {
                PublicKeySnapshotEntry::Complete { kid, public_key } => KeyInfo::Complete {
                    kid: kid.into_string(),
                    member_handle: public_key.protected.subject_handle,
                    created_at: public_key.protected.created_at,
                    expires_at: public_key.protected.expires_at,
                    active,
                    format: public_key.protected.format,
                },
                PublicKeySnapshotEntry::MissingPublicDocument { kid } => KeyInfo::Incomplete {
                    kid: kid.into_string(),
                    member_handle: member_handle.as_str().to_string(),
                    active,
                    missing_document: MissingKeyDocument::PublicJson,
                },
            }
        })
        .collect();

    Ok((member_handle.as_str().to_string(), key_infos))
}

fn resolve_active_kid(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
    kid: Option<String>,
) -> Result<Kid> {
    match kid {
        Some(kid) => resolve_member_kid_query(access, member_handle, &kid),
        None => access
            .load_active_kid(member_handle)?
            .ok_or_else(|| build_no_active_key_error(member_handle.as_str())),
    }
}

fn load_private_key_export_material(
    access: &KeystoreAccess,
    member_handle: MemberHandle,
    kid: Kid,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
) -> Result<PrivateKeyExportMaterial> {
    let (encrypted, public_key) = access.load_key_pair(&member_handle, &kid)?;
    let verified_public_key = verify_public_key_with_attestation_context(
        &public_key,
        KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT,
    )?;
    verify_private_key_matches_public_key(&encrypted, verified_public_key.document())?;

    let plaintext = decrypt_private_key(&encrypted, backend, ssh_pubkey)?;
    verify_private_key_material(&plaintext)?;

    Ok(PrivateKeyExportMaterial {
        plaintext,
        member_handle: member_handle.into_string(),
        kid: kid.into_string(),
        created_at: encrypted.protected.created_at.clone(),
        expires_at: encrypted.protected.expires_at.clone(),
    })
}

/// Activate the key `kid` names, or the newest usable key when it is omitted.
///
/// Omitting the key leaves the choice to the keystore, which makes it under the
/// same lock that publishes the marker. Choosing here first would name a key
/// that a concurrent rotation could remove before the activation reached it.
fn activate_requested_kid(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
    kid: Option<String>,
) -> Result<Kid> {
    let Some(kid) = kid else {
        return access.activate_latest_valid_key(member_handle);
    };
    let kid = resolve_member_kid_query(access, member_handle, &kid)?;
    access.activate_existing_key(member_handle, &kid)?;
    Ok(kid)
}

/// Refuse removing the key this member currently signs with.
///
/// `--force` on `key remove` covers two separate confirmations, so the message
/// names the one being waived here: removing the active key. The other is
/// accepting that the local trust store's approvals stop verifying, reported
/// where that decision is actually made.
fn validate_key_removal(
    member_handle: &MemberHandle,
    kid: &Kid,
    was_active: bool,
    force: bool,
) -> Result<()> {
    if !was_active || force {
        return Ok(());
    }

    Err(Error::build_config_error(format!(
        "Cannot remove active key '{}' because it is the key this member signs with. \
         Run 'kapsaro key activate <other-kid> --member-handle {}' first, or pass --force to \
         remove it anyway. \
         --force also accepts losing the local trust store approvals when the signature \
         cannot be handed to another key.",
        kid, member_handle
    )))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_key_manage_security_test.rs"]
mod service_key_manage_security_test;
