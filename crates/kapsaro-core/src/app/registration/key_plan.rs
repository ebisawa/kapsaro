// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key planning for registration.
//! Decides whether registration reuses an existing key or generates one.

use crate::app::context::options::CommonCommandOptions;
use crate::app::key::generate::KeyGenerationHome;
use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::config::resolution::member_handle::MemberHandleResolver;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::member::find_active_key_document;
use crate::model::identity::MemberHandle;
use crate::support::fs::anchor::AnchoredDir;
use crate::Result;

use super::types::RegistrationKeyPlan;

/// Local state directory opened once for one registration.
///
/// The member handle fallback and the key plan are both answered from this
/// opened directory, so a registration that generates a key writes it into the
/// directory it inspected.
pub struct RegistrationLocalState {
    home: AnchoredDir,
    config: GlobalConfigSnapshot,
    keystore: Option<KeystoreAccess>,
}

/// Open the local state directory a registration works in, creating it when it
/// is not there yet.
///
/// A registration writes its member key into this directory, so it is opened
/// here, before the GitHub binding and the SSH identity are settled, and every
/// later step of the registration works through that one descriptor. The
/// keystore under it is a different matter: a first registration has none, and
/// that is what decides a key has to be generated.
pub fn open_registration_local_state(
    options: &CommonCommandOptions,
) -> Result<RegistrationLocalState> {
    let home = options.ensure_local_state_home()?.clone();
    let config = options.global_config()?.clone();
    let keystore = KeystoreAccess::open_optional_from_anchored_home(&home)?;
    Ok(RegistrationLocalState {
        home,
        config,
        keystore,
    })
}

impl RegistrationLocalState {
    /// Resolve the member handle from non-interactive sources.
    pub fn resolve_optional_member_handle(
        &self,
        member_handle: Option<String>,
    ) -> Result<Option<String>> {
        MemberHandleResolver::fixed(&self.config, self.keystore.as_ref())
            .resolve(member_handle)
            .map(|resolved| resolved.map(MemberHandle::into_string))
    }

    /// Decide whether this member already has a key in the opened keystore.
    pub fn resolve_key_plan(&self, member_handle: &str) -> Result<RegistrationKeyPlan> {
        let Some(keystore) = self.keystore.as_ref() else {
            return Ok(RegistrationKeyPlan::generate_new(
                self.key_generation_home(),
            ));
        };
        let member_handle = MemberHandle::try_from(member_handle)?;
        let Some(active) = find_active_key_document(keystore, &member_handle)? else {
            return Ok(RegistrationKeyPlan::generate_new(
                self.key_generation_home(),
            ));
        };
        Ok(RegistrationKeyPlan::use_existing(
            active.kid,
            active.public_key.protected.expires_at,
            keystore.clone(),
        ))
    }

    fn key_generation_home(&self) -> KeyGenerationHome {
        KeyGenerationHome::from_opened(&self.home)
    }
}
