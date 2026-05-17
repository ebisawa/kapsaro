// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::keystore::member::find_active_key_document;
use crate::Result;

use super::types::RegistrationKeyPlan;

pub fn resolve_registration_key_plan(
    member_handle: &str,
    keystore_root: &std::path::Path,
) -> Result<RegistrationKeyPlan> {
    let Some(active) = find_active_key_document(member_handle, keystore_root)? else {
        return Ok(RegistrationKeyPlan::GenerateNew);
    };

    Ok(RegistrationKeyPlan::UseExisting {
        kid: active.kid,
        expires_at: active.public_key.protected.expires_at,
    })
}
