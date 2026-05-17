// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local decryption key selection.

use super::loader::load_verified_private_key_from_keystore;
use super::{CryptoContext, DecryptionKeyInfo, DecryptionKeyResolution};
use crate::model::common::WrapSet;
use crate::model::identity::Kid;
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, ErrorKind, Result};

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

        for kid in &candidates {
            if kid == &self.kid {
                return Ok(DecryptionKeyResolution::Active {
                    private_key: &self.private_key,
                    info: DecryptionKeyInfo {
                        kid: kid.to_string(),
                        expires_at: self.expires_at.as_str().to_string(),
                        used_fallback: false,
                    },
                });
            }

            let Some(local_key_access) = self.local_key_access.as_ref() else {
                continue;
            };

            match load_verified_private_key_from_keystore(
                &local_key_access.keystore_root,
                member_handle,
                kid.as_str(),
                local_key_access.ssh_backend.as_ref(),
                &local_key_access.ssh_pubkey,
                debug_enabled,
            ) {
                Ok(loaded) => {
                    return Ok(DecryptionKeyResolution::Fallback {
                        private_key: Box::new(loaded.private_key),
                        info: DecryptionKeyInfo {
                            kid: kid.to_string(),
                            expires_at: loaded.expires_at.as_str().to_string(),
                            used_fallback: true,
                        },
                    });
                }
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
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
