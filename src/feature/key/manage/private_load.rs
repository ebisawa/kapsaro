// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::key::material::validate_private_key_material;
use crate::feature::key::protection::encryption::decrypt_private_key;
use crate::feature::verify::private_key::verify_private_key_matches_public_key;
use crate::feature::verify::public_key::{
    verify_public_key_with_attestation_context, KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT,
};
use crate::io::keystore::storage::load_private_key;
use crate::io::keystore::storage::load_public_key;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::private_key::PrivateKeyPlaintext;
use crate::Result;
use std::path::PathBuf;

use super::common::{resolve_active_kid, resolve_keystore_root};

/// Decrypted private key with metadata for portable export.
pub struct PrivateKeyExportMaterial {
    pub plaintext: PrivateKeyPlaintext,
    pub member_id: String,
    pub kid: String,
    pub created_at: String,
    pub expires_at: String,
}

pub fn load_private_key_export_material(
    home: Option<PathBuf>,
    member_id: String,
    kid: Option<String>,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    debug: bool,
) -> Result<PrivateKeyExportMaterial> {
    let keystore_root = resolve_keystore_root(home)?;
    let kid = resolve_active_kid(&keystore_root, &member_id, kid)?;
    let encrypted = load_private_key(&keystore_root, &member_id, &kid)?;

    // Verify the corresponding public.json in the same key directory.
    let public_key = load_public_key(&keystore_root, &member_id, &kid)?;
    let verified_public_key = verify_public_key_with_attestation_context(
        &public_key,
        debug,
        KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT,
    )?;
    verify_private_key_matches_public_key(&encrypted, verified_public_key.document())?;

    let plaintext = decrypt_private_key(&encrypted, backend, ssh_pubkey, debug)?;
    validate_private_key_material(&plaintext)?;

    Ok(PrivateKeyExportMaterial {
        plaintext,
        member_id,
        kid,
        created_at: encrypted.protected.created_at.clone(),
        expires_at: encrypted.protected.expires_at.clone(),
    })
}
