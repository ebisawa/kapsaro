// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local decryption key selection.

use super::loader::load_verified_private_key_from_keystore;
use super::{CryptoContext, DecryptionKeyInfo, DecryptionKeyResolution};
use crate::feature::envelope::wrap_set::WrapSet;
use crate::model::identity::Kid;
use crate::support::kid::{format_kid_display_lossy, format_kid_half_display_lossy};
use crate::{Error, ErrorKind, Result};
use tracing::debug;

impl CryptoContext {
    pub(crate) fn select_local_decryption_key<'a>(
        &'a self,
        wrap_set: &WrapSet,
        member_handle: &str,
        debug_enabled: bool,
    ) -> Result<DecryptionKeyResolution<'a>> {
        let wrap_kids = wrap_set.self_wrap_kids(member_handle);
        let candidates =
            build_candidate_kids(&wrap_kids, self.selected_kid_override.as_ref(), &self.kid);
        if debug_enabled {
            debug!(
                "[CRYPTO] local decryption key: select member_handle={}, explicit_kid={}, wrap_kid_count={}, candidate_count={}",
                member_handle,
                self.selected_kid_override.is_some(),
                wrap_kids.len(),
                candidates.len()
            );
        }

        for kid in &candidates {
            if kid == &self.kid {
                if debug_enabled {
                    debug!(
                        "[CRYPTO] local decryption key: selected active key (kid: {})",
                        format_kid_half_display_lossy(kid.as_str())
                    );
                }
                return Ok(DecryptionKeyResolution::Active {
                    private_key: &self.private_key,
                    info: DecryptionKeyInfo {
                        kid: kid.to_string(),
                        expires_at: self.local_key_expiry.primary_expires_at().to_string(),
                        used_fallback: false,
                        key_identity: self.local_key_identity.clone(),
                        key_expiry: self.local_key_expiry.clone(),
                    },
                });
            }

            let Some(local_key_access) = self.local_key_access.as_ref() else {
                if debug_enabled {
                    debug!(
                        "[CRYPTO] local decryption key: fallback unavailable (kid: {})",
                        format_kid_half_display_lossy(kid.as_str())
                    );
                }
                continue;
            };
            if debug_enabled {
                debug!(
                    "[CRYPTO] local decryption key: try fallback key (kid: {})",
                    format_kid_half_display_lossy(kid.as_str())
                );
            }

            match load_verified_private_key_from_keystore(
                &local_key_access.keystore_root,
                member_handle,
                kid.as_str(),
                local_key_access.ssh_backend.as_ref(),
                &local_key_access.ssh_pubkey,
                debug_enabled,
            ) {
                Ok(loaded) => {
                    if debug_enabled {
                        debug!(
                            "[CRYPTO] local decryption key: selected fallback key (kid: {})",
                            format_kid_half_display_lossy(kid.as_str())
                        );
                    }
                    return Ok(DecryptionKeyResolution::Fallback {
                        private_key: Box::new(loaded.private_key),
                        info: DecryptionKeyInfo {
                            kid: kid.to_string(),
                            expires_at: loaded.key_expiry.primary_expires_at().to_string(),
                            used_fallback: true,
                            key_identity: loaded.key_identity,
                            key_expiry: loaded.key_expiry,
                        },
                    });
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    if debug_enabled {
                        debug!(
                            "[CRYPTO] local decryption key: fallback key not found (kid: {})",
                            format_kid_half_display_lossy(kid.as_str())
                        );
                    }
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        Err(build_missing_wrap_error(
            member_handle,
            self.selected_kid_override.as_ref(),
            &candidates,
        ))
    }
}

fn build_candidate_kids(
    wrap_kids: &[Kid],
    explicit_kid: Option<&Kid>,
    active_kid: &Kid,
) -> Vec<Kid> {
    if let Some(kid) = explicit_kid {
        return vec![kid.clone()];
    }

    let mut candidates = Vec::new();
    if wrap_kids.iter().any(|kid| kid == active_kid) {
        candidates.push(active_kid.clone());
    }
    for kid in wrap_kids {
        if candidates.contains(kid) {
            continue;
        }
        candidates.push(kid.clone());
    }
    candidates
}

fn build_missing_wrap_error(
    member_handle: &str,
    explicit_kid: Option<&Kid>,
    searched_kids: &[Kid],
) -> Error {
    match explicit_kid {
        Some(kid) => Error::build_crypto_error(format!(
            "No wrap found for kid '{}' (member: {})",
            format_kid_display_lossy(kid.as_str()),
            member_handle
        )),
        None => {
            let searched = searched_kids
                .iter()
                .map(|kid| format_kid_display_lossy(kid.as_str()))
                .collect::<Vec<_>>()
                .join(", ");
            Error::build_crypto_error(format!(
                "No wrap found for any local kid [{}] (member: {})",
                searched, member_handle
            ))
        }
    }
}
