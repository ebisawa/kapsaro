// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local decryption key selection.

use super::loader::load_verified_private_key_from_keystore;
use super::{CryptoContext, DecryptionKeyInfo, DecryptionKeyResolution};
use crate::model::common::WrapItem;
use crate::model::identity::Kid;
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, Result};

impl CryptoContext {
    pub(crate) fn select_local_decryption_key<'a>(
        &'a self,
        wrap_items: &[WrapItem],
        member_id: &str,
        debug_enabled: bool,
    ) -> Result<DecryptionKeyResolution<'a>> {
        let wrap_kids = collect_self_wrap_kids(wrap_items, member_id);
        let candidates =
            build_candidate_kids(&wrap_kids, self.selected_kid_override.as_deref(), &self.kid);

        for kid in &candidates {
            if kid == self.kid.as_ref() {
                return Ok(DecryptionKeyResolution::Active {
                    private_key: &self.private_key,
                    info: DecryptionKeyInfo {
                        kid: kid.clone(),
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
                member_id,
                kid,
                local_key_access.ssh_backend.as_ref(),
                &local_key_access.ssh_pubkey,
                debug_enabled,
            ) {
                Ok(loaded) => {
                    return Ok(DecryptionKeyResolution::Fallback {
                        private_key: Box::new(loaded.private_key),
                        info: DecryptionKeyInfo {
                            kid: kid.clone(),
                            expires_at: loaded.expires_at.as_str().to_string(),
                            used_fallback: true,
                        },
                    });
                }
                Err(Error::NotFound { .. }) => continue,
                Err(error) => return Err(error),
            }
        }

        Err(build_missing_wrap_error(
            member_id,
            self.selected_kid_override.as_deref(),
            &candidates,
        ))
    }
}

fn collect_self_wrap_kids(wrap_items: &[WrapItem], member_id: &str) -> Vec<String> {
    let mut kids = Vec::new();
    for wrap_item in wrap_items {
        if wrap_item.rid != member_id || kids.contains(&wrap_item.kid) {
            continue;
        }
        kids.push(wrap_item.kid.clone());
    }
    kids
}

fn build_candidate_kids(
    wrap_kids: &[String],
    explicit_kid: Option<&str>,
    active_kid: &Kid,
) -> Vec<String> {
    if let Some(kid) = explicit_kid {
        return vec![kid.to_string()];
    }

    let mut candidates = Vec::new();
    if wrap_kids.iter().any(|kid| kid == active_kid.as_ref()) {
        candidates.push(active_kid.to_string());
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
    member_id: &str,
    explicit_kid: Option<&str>,
    searched_kids: &[String],
) -> Error {
    match explicit_kid {
        Some(kid) => Error::Crypto {
            message: format!(
                "No wrap found for kid '{}' (member: {})",
                format_kid_display_lossy(kid),
                member_id
            ),
            source: None,
        },
        None => {
            let searched = searched_kids
                .iter()
                .map(|kid| format_kid_display_lossy(kid))
                .collect::<Vec<_>>()
                .join(", ");
            Error::Crypto {
                message: format!(
                    "No wrap found for any local kid [{}] (member: {})",
                    searched, member_id
                ),
                source: None,
            }
        }
    }
}
