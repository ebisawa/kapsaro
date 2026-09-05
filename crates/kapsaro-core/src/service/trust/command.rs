// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Fixed local-state capabilities for explicit trust-store commands.
//! Binds the owner, signing key, home, keystore, and trust directory once.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use crate::io::keystore::access::{build_missing_keystore_error, KeystoreAccess};
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::io::trust::paths::{get_trust_store_file_path, TRUST_DIR_NAME};
use crate::service::config::LocalStateSession;
use crate::service::key::{KeyContext, MemberHandle};
use crate::support::fs::anchor::AnchoredDir;
#[cfg(test)]
use crate::support::fs::relative::DirectoryScope;
use crate::support::fs::relative::{
    ensure_child_dir_restricted_at, open_dir_identity, open_optional_child_dir, DirectoryFd,
    OpenDir,
};
use crate::{Error, Result};

/// One trust command's fixed local-state and signing capabilities.
pub struct TrustCommandSession {
    home: AnchoredDir,
    trust_dir: OnceLock<Arc<OpenDir>>,
    key_ctx: KeyContext,
    owner: MemberHandle,
    path: PathBuf,
}

impl TrustCommandSession {
    /// Bind an explicit home and already selected signing key to one owner.
    pub fn open(
        local_state: &LocalStateSession,
        owner: MemberHandle,
        key_ctx: KeyContext,
    ) -> Result<Self> {
        if key_ctx.member_handle() != &owner {
            return Err(Error::build_invalid_argument_error(
                "Trust command owner does not match the selected signing key",
            ));
        }
        let home = local_state.home().cloned().ok_or_else(|| {
            build_missing_keystore_error(
                &get_keystore_root_from_base(local_state.base_dir()),
                &owner,
            )
        })?;
        let keystore = key_ctx.inner().local_keystore_access().ok_or_else(|| {
            build_missing_keystore_error(
                &get_keystore_root_from_base(local_state.base_dir()),
                &owner,
            )
        })?;
        ensure_key_home_matches(&home, keystore)?;
        let trust_dir = fixed_optional_trust_directory(&home)?;
        let path = get_trust_store_file_path(home.path(), &owner);
        Ok(Self {
            home,
            trust_dir,
            key_ctx,
            owner,
            path,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        base_dir: impl AsRef<Path>,
        owner: MemberHandle,
        key_ctx: KeyContext,
    ) -> Result<Self> {
        let base_dir = base_dir.as_ref();
        let home = AnchoredDir::open(
            base_dir.to_path_buf(),
            DirectoryScope::LocalState,
            "local state root",
        )?;
        let trust_dir = fixed_optional_trust_directory(&home)?;
        let path = get_trust_store_file_path(home.path(), &owner);
        Ok(Self {
            home,
            trust_dir,
            key_ctx,
            owner,
            path,
        })
    }

    pub(crate) fn home(&self) -> &AnchoredDir {
        &self.home
    }

    pub(crate) fn trust_dir(&self) -> Option<&Arc<OpenDir>> {
        self.trust_dir.get()
    }

    pub(crate) fn key_ctx(&self) -> &KeyContext {
        &self.key_ctx
    }

    pub(crate) fn keystore(&self) -> &KeystoreAccess {
        self.key_ctx
            .inner()
            .local_keystore_access()
            .expect("TrustCommandSession validates a local keystore")
    }

    pub(crate) fn owner(&self) -> &MemberHandle {
        &self.owner
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn ensured_trust_directory(&self) -> Result<&Arc<OpenDir>> {
        if self.trust_dir.get().is_none() {
            let opened = Arc::new(ensure_child_dir_restricted_at(&self.home, TRUST_DIR_NAME)?);
            let _ = self.trust_dir.set(opened);
        }
        Ok(self
            .trust_dir
            .get()
            .expect("trust directory is fixed after successful creation"))
    }
}

fn fixed_optional_trust_directory(home: &AnchoredDir) -> Result<OnceLock<Arc<OpenDir>>> {
    let fixed = OnceLock::new();
    if let Some(trust_dir) = open_optional_child_dir(home, TRUST_DIR_NAME)? {
        let _ = fixed.set(Arc::new(trust_dir));
    }
    Ok(fixed)
}

fn ensure_key_home_matches(home: &AnchoredDir, keystore: &KeystoreAccess) -> Result<()> {
    let key_home = keystore.home().ok_or_else(|| {
        Error::build_invalid_operation_error(
            "Selected signing key is not bound to a local-state home".to_string(),
        )
    })?;
    if open_dir_identity(home)? == open_dir_identity(key_home)? {
        return Ok(());
    }
    Err(Error::build_invalid_operation_error(
        "Selected signing key belongs to a different local-state home".to_string(),
    ))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_trust_command_test.rs"]
mod service_trust_command_test;
