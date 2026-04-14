// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common test utilities for environment variable management

// Test-only key generation helpers
#[path = "../tests/test_utils/constants.rs"]
#[allow(dead_code)]
mod constants;
#[path = "../tests/test_utils/crypto_context.rs"]
pub mod crypto_context;
#[path = "../tests/test_utils/ed25519_backend.rs"]
pub mod ed25519_backend;
#[path = "../tests/test_utils/fixture.rs"]
mod fixture;
#[allow(dead_code)]
pub mod keygen_helpers;
#[path = "../tests/test_utils/ssh_stubs.rs"]
#[allow(dead_code)]
mod ssh_stubs;
#[allow(unused_imports)]
pub use constants::{
    ALICE_MEMBER_ID, BOB_MEMBER_ID, CAROL_MEMBER_ID, DAVE_MEMBER_ID, EVE_MEMBER_ID,
    FRANK_MEMBER_ID, TEST_MEMBER_ID,
};
#[allow(unused_imports)]
pub use crypto_context::setup_member_key_context;
#[allow(unused_imports)]
pub use fixture::{
    create_temp_ssh_keypair_in_dir, load_fixture_ssh_pubkey, save_public_key, setup_test_keystore,
    setup_test_keystore_from_fixtures, setup_test_workspace, setup_test_workspace_from_fixtures,
};
#[allow(unused_imports)]
pub use keygen_helpers::{create_test_private_key, keygen_test};
use secretenv::model::identity::{Kid, MemberId};
use secretenv::{io::keystore::member::find_active_key_document, Error};
#[allow(unused_imports)]
pub use ssh_stubs::{stub_agent_signer, stub_ssh_keygen};

#[allow(dead_code)]
pub fn member_id(value: impl Into<String>) -> MemberId {
    MemberId::try_from(value.into()).expect("test member_id must be valid")
}

#[allow(dead_code)]
pub fn kid(value: impl Into<String>) -> Kid {
    Kid::try_from(value.into()).expect("test kid must be valid")
}

/// Set up a trust store that approves all active members in a workspace.
///
/// Creates `<home>/trust/<owner_member_id>.json` with all active members'
/// kids pre-approved. Used by CLI integration tests to pass trust checks.
pub fn setup_trust_store_for_workspace(
    home: &std::path::Path,
    workspace_path: &std::path::Path,
    owner_member_id: &str,
    key_ctx: &secretenv::feature::context::crypto::CryptoContext,
) {
    use secretenv::feature::trust::signature::sign_trust_store;
    use secretenv::io::trust::paths::trust_store_file_path;
    use secretenv::io::trust::store::save_trust_store;
    use secretenv::io::workspace::members::load_active_member_files;
    use secretenv::model::identifiers::format::TRUST_LOCAL_V2;
    use secretenv::model::trust_store::{KnownKey, KnownKeyApprovalVia, TrustStoreProtected};
    use std::collections::BTreeMap;

    let active_members = load_active_member_files(workspace_path).unwrap();
    let known_keys: Vec<KnownKey> = active_members
        .iter()
        .map(|pk| KnownKey {
            kid: pk.protected.kid.clone(),
            member_id: pk.protected.member_id.clone(),
            approved_at: "2026-01-01T00:00:00Z".to_string(),
            approved_via: KnownKeyApprovalVia::ManualReview,
            evidence: None,
            extra: BTreeMap::new(),
        })
        .collect();

    let now = "2026-01-01T00:00:00Z".to_string();
    let protected = TrustStoreProtected {
        format: TRUST_LOCAL_V2.to_string(),
        owner_member_id: owner_member_id.to_string(),
        created_at: now.clone(),
        updated_at: now,
        known_keys,
    };

    let doc = sign_trust_store(&protected, &key_ctx.signing_key, &key_ctx.kid).unwrap();
    let path = trust_store_file_path(home, owner_member_id);
    save_trust_store(&path, &doc).unwrap();
}

/// Generate and activate a new test key for a member with the requested expires_at.
pub fn update_active_private_key_expires_at(home: &Path, member_id: &str, expires_at: &str) {
    use secretenv::feature::key::generate::{generate_key, KeyGenerationOptions};
    use secretenv::feature::key::ssh_binding::SshBindingContext;
    use secretenv::io::ssh::backend::ssh_keygen::SshKeygenBackend;
    use secretenv::io::ssh::backend::SignatureBackend;
    use secretenv::io::ssh::external::keygen::DefaultSshKeygen;
    use secretenv::io::ssh::protocol::{build_sha256_fingerprint, SshKeyDescriptor};
    use secretenv::model::ssh::SshDeterminismStatus;

    let ssh_key_path = home.join(".ssh").join("test_ed25519");
    let ssh_pubkey = std::fs::read_to_string(home.join(".ssh").join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let created_at =
        secretenv::support::time::build_timestamp_display(time::OffsetDateTime::now_utc()).unwrap();
    let ssh_binding = SshBindingContext {
        public_key: ssh_pubkey.clone(),
        fingerprint: build_sha256_fingerprint(&ssh_pubkey).unwrap(),
        backend: Box::new(SshKeygenBackend::new(
            Box::new(DefaultSshKeygen::new("ssh-keygen")),
            SshKeyDescriptor::from_path(ssh_key_path),
        )) as Box<dyn SignatureBackend>,
        determinism: SshDeterminismStatus::Verified,
    };

    generate_key(KeyGenerationOptions {
        member_id: member_id.to_string(),
        home: Some(home.to_path_buf()),
        created_at,
        expires_at: expires_at.to_string(),
        no_activate: false,
        debug: false,
        github_account: None,
        verbose: false,
        ssh_binding,
    })
    .unwrap();
}

pub fn build_expiring_soon_timestamp(days_from_now: i64) -> String {
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::days(days_from_now);
    secretenv::support::time::build_timestamp_display(expires_at).unwrap()
}

pub fn sync_active_public_key_to_workspace(
    home: &Path,
    workspace: &Path,
    member_id: &str,
) -> Result<(), Error> {
    let active_key = find_active_key_document(member_id, &home.join("keys"))?.ok_or_else(|| {
        Error::NotFound {
            message: format!("Active key not found for member: {}", member_id),
        }
    })?;
    let member_path = workspace
        .join("members")
        .join("active")
        .join(format!("{member_id}.json"));
    std::fs::write(
        &member_path,
        serde_json::to_string_pretty(&active_key.public_key).unwrap(),
    )
    .map_err(|error| {
        Error::io_with_source(
            format!(
                "Failed to write workspace member file: {}",
                member_path.display()
            ),
            error,
        )
    })
}

// Used by library tests (via crate::test_utils) — not referenced in the integration test binary.
#[allow(dead_code)]
pub fn stage_active_public_key_to_workspace_incoming(
    home: &Path,
    workspace: &Path,
    member_id: &str,
) -> Result<(), Error> {
    let active_key = find_active_key_document(member_id, &home.join("keys"))?.ok_or_else(|| {
        Error::NotFound {
            message: format!("Active key not found for member: {}", member_id),
        }
    })?;
    let member_path = workspace
        .join("members")
        .join("incoming")
        .join(format!("{member_id}.json"));
    std::fs::write(
        &member_path,
        serde_json::to_string_pretty(&active_key.public_key).unwrap(),
    )
    .map_err(|error| {
        Error::io_with_source(
            format!(
                "Failed to write workspace incoming member file: {}",
                member_path.display()
            ),
            error,
        )
    })
}

use std::path::Path;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct CwdGuard {
    original: PathBuf,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl CwdGuard {
    fn enter(dir: &Path) -> Self {
        let lock = lock_unpoisoned(CWD_LOCK.get_or_init(|| Mutex::new(())));
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        Self {
            original,
            _lock: lock,
        }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}

/// Run a closure with the process current directory temporarily changed.
///
/// This is serialized via a global mutex because the current directory is
/// process-global and Rust tests run in parallel by default.
pub fn with_temp_cwd<R>(dir: &Path, f: impl FnOnce() -> R) -> R {
    let _guard = CwdGuard::enter(dir);
    f()
}

/// Global mutex for tests that modify environment variables.
/// All tests that modify environment variables must hold this lock.
pub static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// RAII guard that holds the env mutex and restores env vars on drop.
pub struct EnvGuard {
    vars: Vec<(String, Option<String>)>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub fn new(keys: &[&str]) -> Self {
        let lock = lock_unpoisoned(&ENV_MUTEX);
        let vars = keys
            .iter()
            .map(|&k| (k.to_string(), std::env::var(k).ok()))
            .collect();
        Self { vars, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.vars {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::lock_unpoisoned;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Mutex;

    #[test]
    fn test_lock_unpoisoned_returns_guard_for_healthy_mutex() {
        let mutex = Mutex::new(42_u8);
        let guard = lock_unpoisoned(&mutex);
        assert_eq!(*guard, 42);
    }

    #[test]
    fn test_lock_unpoisoned_recovers_from_poisoned_mutex() {
        let mutex = Mutex::new(7_u8);

        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = mutex.lock().unwrap();
            panic!("poison test mutex");
        }));

        let guard = lock_unpoisoned(&mutex);
        assert_eq!(*guard, 7);
    }
}
