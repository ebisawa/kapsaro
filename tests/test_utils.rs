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
#[allow(unused_imports)]
pub use constants::{
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, CAROL_MEMBER_HANDLE, TEST_MEMBER_HANDLE,
};
pub use crypto_context::setup_member_key_context;
#[allow(unused_imports)]
pub use fixture::{
    generate_temp_ssh_keypair_in_dir, setup_test_keystore, setup_test_keystore_from_fixtures,
    setup_test_workspace, setup_test_workspace_from_fixtures,
};
use kapsaro_core::cli_api::test_support::storage::keystore::member::find_active_key_document;
use kapsaro_core::Error;
#[allow(unused_imports)]
pub use keygen_helpers::keygen_test;

/// Set up a trust store that approves all active members in a workspace.
///
/// Creates `<home>/trust/<owner_handle>.json` with all active members'
/// kids pre-approved. Used by CLI integration tests to pass trust checks.
pub fn setup_trust_store_for_workspace(
    home: &std::path::Path,
    workspace_path: &std::path::Path,
    owner_handle: &str,
    key_ctx: &kapsaro_core::cli_api::test_support::operations::context::crypto::CryptoContext,
) {
    use kapsaro_core::cli_api::test_support::domain::trust_store::{
        KnownKey, KnownKeyApprovalVia, TrustStoreProtected,
    };
    use kapsaro_core::cli_api::test_support::domain::wire::format::LOCAL_TRUST_V1;
    use kapsaro_core::cli_api::test_support::operations::trust::signature::sign_trust_store;
    use kapsaro_core::cli_api::test_support::storage::trust::paths::get_trust_store_file_path;
    use kapsaro_core::cli_api::test_support::storage::trust::store::save_trust_store;
    use kapsaro_core::cli_api::test_support::storage::workspace::members::load_active_member_files;
    use std::collections::BTreeMap;

    let active_members = load_active_member_files(workspace_path).unwrap();
    let known_keys: Vec<KnownKey> = active_members
        .iter()
        .map(|pk| KnownKey {
            kid: pk.protected.kid.clone(),
            subject_handle: pk.protected.subject_handle.clone(),
            approved_at: "2026-01-01T00:00:00Z".to_string(),
            approved_via: KnownKeyApprovalVia::ManualReview,
            evidence: None,
            extra: BTreeMap::new(),
        })
        .collect();

    let now = "2026-01-01T00:00:00Z".to_string();
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: owner_handle.to_string(),
        created_at: now.clone(),
        updated_at: now,
        known_keys,
        recipient_sets: Vec::new(),
    };

    let doc = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let path = get_trust_store_file_path(home, owner_handle);
    save_trust_store(&path, &doc).unwrap();
}

/// Generate and activate a new test key for a member with the requested expires_at.
pub fn update_active_private_key_expires_at(home: &Path, member_handle: &str, expires_at: &str) {
    use kapsaro_core::cli_api::test_support::domain::ssh::SshDeterminismStatus;
    use kapsaro_core::cli_api::test_support::operations::key::generate::{
        generate_key, KeyGenerationOptions,
    };
    use kapsaro_core::cli_api::test_support::operations::key::ssh_binding::SshBindingContext;
    use kapsaro_core::cli_api::test_support::storage::ssh::backend::ssh_keygen::SshKeygenBackend;
    use kapsaro_core::cli_api::test_support::storage::ssh::backend::SignatureBackend;
    use kapsaro_core::cli_api::test_support::storage::ssh::external::keygen::DefaultSshKeygen;
    use kapsaro_core::cli_api::test_support::storage::ssh::protocol::fingerprint::build_sha256_fingerprint;
    use kapsaro_core::cli_api::test_support::storage::ssh::protocol::key_descriptor::SshKeyDescriptor;

    let ssh_key_path = home.join(".ssh").join("test_ed25519");
    let ssh_pubkey = std::fs::read_to_string(home.join(".ssh").join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let created_at = kapsaro_core::cli_api::test_support::helpers::time::format_timestamp_rfc3339(
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
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
        member_handle: member_handle.to_string(),
        created_at,
        expires_at: expires_at.to_string(),
        debug: false,
        github_account: None,
        ssh_binding,
    })
    .map(|result| {
        let keystore_root = home.join("keys");
        kapsaro_core::cli_api::test_support::storage::keystore::storage::save_key_pair_atomic(
            &keystore_root,
            member_handle,
            &result.kid,
            &result.private_key,
            &result.public_key,
        )
        .unwrap();
        kapsaro_core::cli_api::test_support::storage::keystore::active::set_active_kid(
            member_handle,
            &result.kid,
            &keystore_root,
        )
        .unwrap();
    })
    .unwrap();
}

pub fn build_expiring_soon_timestamp(days_from_now: i64) -> String {
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::days(days_from_now);
    kapsaro_core::cli_api::test_support::helpers::time::format_timestamp_rfc3339(expires_at)
        .unwrap()
}

pub fn save_active_public_key_to_workspace(
    home: &Path,
    workspace: &Path,
    member_handle: &str,
) -> Result<(), Error> {
    save_active_public_key_to_workspace_dir(home, workspace, member_handle, "active")
}

pub fn save_active_public_key_to_workspace_incoming(
    home: &Path,
    workspace: &Path,
    member_handle: &str,
) -> Result<(), Error> {
    save_active_public_key_to_workspace_dir(home, workspace, member_handle, "incoming")
}

fn save_active_public_key_to_workspace_dir(
    home: &Path,
    workspace: &Path,
    member_handle: &str,
    member_dir: &str,
) -> Result<(), Error> {
    let active_key =
        find_active_key_document(member_handle, &home.join("keys"))?.ok_or_else(|| {
            Error::build_not_found_error(format!(
                "Active key not found for member: {}",
                member_handle
            ))
        })?;
    let member_path = workspace
        .join("members")
        .join(member_dir)
        .join(format!("{member_handle}.json"));
    std::fs::write(
        &member_path,
        serde_json::to_string_pretty(&active_key.public_key).unwrap(),
    )
    .map_err(|error| {
        Error::build_io_error_with_source(
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
