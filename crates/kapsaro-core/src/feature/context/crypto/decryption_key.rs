// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local decryption key selection.

use super::loader::load_verified_private_key_from_keystore;
use super::{CryptoContext, DecryptionKeyInfo, DecryptionKeyResolution, PrivateKeyLoadResult};
use crate::feature::envelope::wrap_set::WrapSet;
use crate::model::identity::{Kid, MemberHandle};
use crate::support::kid::{format_kid_display_lossy, format_kid_half_display_lossy};
use crate::{Error, ErrorKind, Result};
use tracing::debug;

impl CryptoContext {
    pub(crate) fn select_local_decryption_key<'a>(
        &'a self,
        wrap_set: &WrapSet,
        member_handle: &str,
    ) -> Result<DecryptionKeyResolution<'a>> {
        let keystore_member_handle = MemberHandle::try_from(member_handle)?;
        let wrap_kid = wrap_set.self_wrap_kid(&keystore_member_handle);
        let candidate = select_candidate_kid(wrap_kid, self.selected_kid_override.as_ref());
        debug!(
            "[CRYPTO] local decryption key: select member_handle={}, explicit_kid={}, wrap_kid_count={}, candidate_count={}",
            member_handle,
            self.selected_kid_override.is_some(),
            usize::from(wrap_kid.is_some()),
            usize::from(candidate.is_some())
        );

        if let Some(kid) = &candidate {
            if kid == &self.kid {
                return Ok(self.active_decryption_key(kid));
            }

            if let Some(resolution) = self.load_fallback_key(&keystore_member_handle, kid)? {
                return Ok(resolution);
            }
        }

        Err(build_missing_decryption_key_error(
            member_handle,
            self.selected_kid_override.as_ref(),
            candidate.as_ref(),
            judge_missing_decryption_key(wrap_kid, candidate.as_ref()),
        ))
    }

    /// The key this context already holds, when the search settled on its id.
    fn active_decryption_key(&self, kid: &Kid) -> DecryptionKeyResolution<'_> {
        debug!(
            "[CRYPTO] local decryption key: selected active key (kid: {})",
            format_kid_half_display_lossy(kid.as_str())
        );
        DecryptionKeyResolution::Active {
            private_key: &self.private_key,
            info: DecryptionKeyInfo {
                kid: kid.clone(),
                expires_at: self.local_key_expiry.primary_expires_at().to_string(),
                used_fallback: false,
                key_identity: self.local_key_identity.clone(),
                key_expiry: self.local_key_expiry.clone(),
            },
        }
    }

    /// Open the keystore copy of a key that is not the active one.
    ///
    /// `None` means the caller has to report the key as unavailable: either no
    /// keystore is reachable, or the keystore holds nothing under this key id.
    fn load_fallback_key(
        &self,
        keystore_member_handle: &MemberHandle,
        kid: &Kid,
    ) -> Result<Option<DecryptionKeyResolution<'_>>> {
        let shown_kid = format_kid_half_display_lossy(kid.as_str());
        let Some(local_key_access) = self.local_key_access.as_ref() else {
            debug!("[CRYPTO] local decryption key: fallback unavailable (kid: {shown_kid})");
            return Ok(None);
        };
        debug!("[CRYPTO] local decryption key: try fallback key (kid: {shown_kid})");

        match load_verified_private_key_from_keystore(
            &local_key_access.keystore_access,
            keystore_member_handle,
            kid,
            local_key_access.ssh_backend.as_ref(),
            &local_key_access.ssh_pubkey,
        ) {
            Ok(loaded) => {
                debug!("[CRYPTO] local decryption key: selected fallback key (kid: {shown_kid})");
                Ok(Some(build_fallback_resolution(loaded, kid)))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                debug!("[CRYPTO] local decryption key: fallback key not found (kid: {shown_kid})");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

/// Wrap a key opened from the keystore as the fallback the search settled on.
fn build_fallback_resolution<'a>(
    loaded: PrivateKeyLoadResult,
    kid: &Kid,
) -> DecryptionKeyResolution<'a> {
    DecryptionKeyResolution::Fallback {
        private_key: Box::new(loaded.private_key),
        info: DecryptionKeyInfo {
            kid: kid.clone(),
            expires_at: loaded.key_expiry.primary_expires_at().to_string(),
            used_fallback: true,
            key_identity: loaded.key_identity,
            key_expiry: loaded.key_expiry,
        },
    }
}

/// The one key id worth opening, which an explicit selection overrides.
fn select_candidate_kid(wrap_kid: Option<&Kid>, explicit_kid: Option<&Kid>) -> Option<Kid> {
    explicit_kid.or(wrap_kid).cloned()
}

/// Which half of the pair a decryption needs was the one that was missing.
///
/// The two are repaired in different places, so a report that does not tell
/// them apart sends the operator to the wrong one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MissingDecryptionKey {
    /// Nothing in the artifact is wrapped to the key id that was searched for.
    Wrap,
    /// The artifact holds a wrap for that key id, and the keystore holds no key
    /// under it.
    LocalKey,
}

/// Say which of the two was missing, from what the search had to work with.
///
/// The searched key id is the wrap's own only when no explicit selection
/// overrode it, and that is the single case where a wrap for it is known to
/// exist. An explicit selection naming another key, or a search with no wrap to
/// go on, has no wrap behind it whatever the keystore holds.
fn judge_missing_decryption_key(
    wrap_kid: Option<&Kid>,
    searched_kid: Option<&Kid>,
) -> MissingDecryptionKey {
    match (wrap_kid, searched_kid) {
        (Some(wrap_kid), Some(searched_kid)) if wrap_kid == searched_kid => {
            MissingDecryptionKey::LocalKey
        }
        _ => MissingDecryptionKey::Wrap,
    }
}

/// Report the key that could not be selected as what was actually missing.
///
/// A key id the artifact wraps to but the keystore no longer holds is the shape
/// a rotation leaves behind once the old key is removed. Reporting it as a
/// missing wrap would send the operator to the artifact's recipients, which are
/// intact, instead of to the key.
fn build_missing_decryption_key_error(
    member_handle: &str,
    explicit_kid: Option<&Kid>,
    searched_kid: Option<&Kid>,
    missing: MissingDecryptionKey,
) -> Error {
    let searched = searched_kid
        .map(|kid| format_kid_display_lossy(kid.as_str()))
        .unwrap_or_default();
    let message = match (missing, explicit_kid) {
        (MissingDecryptionKey::LocalKey, _) => format!(
            "Wrap found for kid '{}', but no local key with that kid is in the keystore \
             (member: {})",
            searched, member_handle
        ),
        (MissingDecryptionKey::Wrap, Some(_)) => format!(
            "No wrap found for kid '{}' (member: {})",
            searched, member_handle
        ),
        (MissingDecryptionKey::Wrap, None) => format!(
            "No wrap found for any local kid [{}] (member: {})",
            searched, member_handle
        ),
    };
    Error::build_crypto_error(message)
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/feature_context_crypto_decryption_key_test.rs"]
mod feature_context_crypto_decryption_key_test;
