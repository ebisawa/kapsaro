// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use super::keygen_helpers::{build_test_private_key, keygen_test};
use secretenv_core::cli_api::test_support::domain::private_key::PrivateKey;
use secretenv_core::cli_api::test_support::domain::public_key::PublicKey;
use secretenv_core::cli_api::test_support::storage::keystore::active::set_active_kid;
use secretenv_core::cli_api::test_support::storage::keystore::storage::save_key_pair_atomic;
use tempfile::TempDir;

// ============================================================================
// Shared fixture (runtime-generated test keys)
// ============================================================================

struct MemberFixture {
    kid: String,
    public_key: PublicKey,
    private_key: PrivateKey,
}

struct SharedFixture {
    ssh_private_key_bytes: Vec<u8>,
    ssh_public_key_content: String,
    members: HashMap<String, MemberFixture>,
}

static SHARED_FIXTURE: LazyLock<SharedFixture> = LazyLock::new(build_shared_fixture);

fn ensure_restricted_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn create_secret_home() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    ensure_restricted_dir(temp_dir.path());
    temp_dir
}

fn build_shared_fixture() -> SharedFixture {
    let temp_dir = TempDir::new().expect("Failed to create temp dir for fixture generation");
    let (ssh_priv, _ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&temp_dir);

    let ssh_private_key_bytes =
        fs::read(&ssh_priv).expect("Failed to read generated SSH private key");

    let mut members = HashMap::new();
    for member_handle in ["alice@example.com", "bob@example.com"] {
        let (plaintext, public_key) = keygen_test(member_handle, &ssh_priv, &ssh_pub_content)
            .expect("Failed to generate test key pair");
        let private_key = build_test_private_key(
            &plaintext,
            &public_key.protected.subject_handle,
            &public_key.protected.kid,
            &ssh_priv,
            &ssh_pub_content,
        )
        .expect("Failed to create test private key");

        let kid = public_key.protected.kid.clone();
        members.insert(
            member_handle.to_string(),
            MemberFixture {
                kid,
                public_key,
                private_key,
            },
        );
    }

    // temp_dir is dropped here, cleaning up the ssh-keygen output
    SharedFixture {
        ssh_private_key_bytes,
        ssh_public_key_content: ssh_pub_content,
        members,
    }
}

// ============================================================================
// Fixture loaders
// ============================================================================

/// Write SSH keypair from shared fixture into per-test TempDir
fn save_ssh_keys(temp_dir: &TempDir) -> (PathBuf, String) {
    let fixture = &*SHARED_FIXTURE;
    let ssh_dir = temp_dir.path().join(".ssh");
    ensure_restricted_dir(&ssh_dir);

    let dst_priv = ssh_dir.join("test_ed25519");
    let dst_pub = ssh_dir.join("test_ed25519.pub");
    fs::write(&dst_priv, &fixture.ssh_private_key_bytes).unwrap();
    fs::write(&dst_pub, &fixture.ssh_public_key_content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dst_priv, fs::Permissions::from_mode(0o600)).unwrap();
    }

    (dst_priv, fixture.ssh_public_key_content.clone())
}

/// Install a fixture member into keystore and workspace
fn install_fixture_member(
    member_handle: &str,
    keystore_root: &Path,
    workspace_keystore: Option<&Path>,
    members_dir: &Path,
) {
    let fixture = &*SHARED_FIXTURE;
    let member = fixture
        .members
        .get(member_handle)
        .unwrap_or_else(|| panic!("No fixture for member: {}", member_handle));

    save_key_pair_atomic(
        keystore_root,
        &member.public_key.protected.subject_handle,
        &member.public_key.protected.kid,
        &member.private_key,
        &member.public_key,
    )
    .unwrap();

    if let Some(ws_keystore) = workspace_keystore {
        save_public_key(
            ws_keystore,
            &member.public_key.protected.subject_handle,
            &member.public_key.protected.kid,
            &member.public_key,
        )
        .unwrap();
    }

    let member_file = members_dir.join(format!("{}.json", member_handle));
    fs::write(
        &member_file,
        serde_json::to_string_pretty(&member.public_key).unwrap(),
    )
    .unwrap();
}

/// Setup test keystore from shared fixture (no ssh-keygen calls)
pub fn setup_test_keystore_from_fixtures(member_handle: &str) -> TempDir {
    let temp_dir = create_secret_home();
    save_ssh_keys(&temp_dir);

    let keystore_root = temp_dir.path().join("keys");
    ensure_restricted_dir(&keystore_root);

    let member = SHARED_FIXTURE
        .members
        .get(member_handle)
        .unwrap_or_else(|| panic!("No fixture for member: {}", member_handle));

    let workspace_dir = temp_dir.path().join("workspace");
    let members_dir = workspace_dir.join("members/active");
    ensure_restricted_dir(&members_dir);
    ensure_restricted_dir(&workspace_dir.join("members/incoming"));
    ensure_restricted_dir(&workspace_dir.join("secrets"));

    install_fixture_member(member_handle, &keystore_root, None, &members_dir);
    set_active_kid(member_handle, &member.kid, &keystore_root).unwrap();

    temp_dir
}

/// Setup test workspace from shared fixture (no ssh-keygen calls)
pub fn setup_test_workspace_from_fixtures(member_handles: &[&str]) -> (TempDir, PathBuf) {
    let temp_dir = create_secret_home();
    save_ssh_keys(&temp_dir);

    let workspace_dir = temp_dir.path().join("workspace");
    let workspace_keystore = workspace_dir.join("keystore");
    let members_dir = workspace_dir.join("members/active");
    ensure_restricted_dir(&workspace_keystore);
    ensure_restricted_dir(&members_dir);
    ensure_restricted_dir(&workspace_dir.join("members/incoming"));
    ensure_restricted_dir(&workspace_dir.join("secrets"));

    let base_keystore = temp_dir.path().join("keys");
    ensure_restricted_dir(&base_keystore);

    for member_handle in member_handles {
        install_fixture_member(
            member_handle,
            &base_keystore,
            Some(&workspace_keystore),
            &members_dir,
        );
    }

    (temp_dir, workspace_dir)
}

/// Save PublicKey only to keystore (test helper)
///
/// For saving both keys, use `save_key_pair_atomic` from production code instead.
pub fn save_public_key(
    keystore_root: &Path,
    member_handle: &str,
    kid: &str,
    public_key: &secretenv_core::cli_api::test_support::domain::public_key::PublicKey,
) -> secretenv_core::Result<()> {
    let dir = keystore_root.join(member_handle).join(kid);
    ensure_restricted_dir(&dir);
    secretenv_core::cli_api::test_support::helpers::fs::atomic::save_json(
        &dir.join("public.json"),
        public_key,
    )
}

/// Helper to create a temporary SSH Ed25519 keypair for testing
///
/// Returns: (private_key_path, public_key_path, public_key_content)
pub fn generate_temp_ssh_keypair_in_dir(temp_dir: &TempDir) -> (PathBuf, PathBuf, String) {
    let ssh_dir = temp_dir.path().join(".ssh");
    ensure_restricted_dir(&ssh_dir);

    let private_key_path = ssh_dir.join("test_ed25519");
    let public_key_path = ssh_dir.join("test_ed25519.pub");

    let output = std::process::Command::new("ssh-keygen")
        .arg("-t")
        .arg(secretenv_core::cli_api::test_support::storage::ssh::protocol::constants::KEYGEN_TYPE_ED25519)
        .arg("-f")
        .arg(&private_key_path)
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg("test@example.com")
        .output()
        .expect("Failed to spawn ssh-keygen");
    assert!(
        output.status.success(),
        "ssh-keygen failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let public_key_content = fs::read_to_string(&public_key_path)
        .expect("Failed to read public key")
        .trim()
        .to_string();

    (private_key_path, public_key_path, public_key_content)
}

/// Setup test workspace with members directory and public keys
pub fn setup_test_workspace(member_handles: &[&str]) -> (TempDir, PathBuf) {
    let temp_dir = create_secret_home();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&temp_dir);

    let workspace_dir = temp_dir.path().join("workspace");
    let workspace_keystore = workspace_dir.join("keystore");
    let members_dir = workspace_dir.join("members/active");
    let secrets_dir = workspace_dir.join("secrets");
    ensure_restricted_dir(&workspace_keystore);
    ensure_restricted_dir(&members_dir);
    ensure_restricted_dir(&workspace_dir.join("members/incoming"));
    ensure_restricted_dir(&secrets_dir);

    let base_keystore = temp_dir.path().join("keys");
    ensure_restricted_dir(&base_keystore);

    for member_handle in member_handles {
        let (private_key, public_key) =
            keygen_test(member_handle, &ssh_priv, &ssh_pub_content).unwrap();
        let private_key_doc = build_test_private_key(
            &private_key,
            &public_key.protected.subject_handle,
            &public_key.protected.kid,
            &ssh_priv,
            &ssh_pub_content,
        )
        .unwrap();

        save_key_pair_atomic(
            &base_keystore,
            &public_key.protected.subject_handle,
            &public_key.protected.kid,
            &private_key_doc,
            &public_key,
        )
        .unwrap();

        set_active_kid(
            &public_key.protected.subject_handle,
            &public_key.protected.kid,
            &base_keystore,
        )
        .unwrap();

        save_public_key(
            &workspace_keystore,
            &public_key.protected.subject_handle,
            &public_key.protected.kid,
            &public_key,
        )
        .unwrap();

        let member_file = members_dir.join(format!("{}.json", member_handle));
        fs::write(
            &member_file,
            serde_json::to_string_pretty(&public_key).unwrap(),
        )
        .unwrap();
    }

    // Write config.toml with the first member handle for auto-resolution
    if let Some(first_member_handle) = member_handles.first() {
        let config_path = temp_dir.path().join("config.toml");
        fs::write(
            &config_path,
            format!("member_handle = \"{}\"\n", first_member_handle),
        )
        .unwrap();
    }

    (temp_dir, workspace_dir)
}

/// Setup test environment with keystore and test keys
pub fn setup_test_keystore(member_handle: &str) -> TempDir {
    let temp_dir = create_secret_home();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&temp_dir);

    let keystore_root = temp_dir.path().join("keys");
    ensure_restricted_dir(&keystore_root);

    let (private_key, public_key) =
        keygen_test(member_handle, &ssh_priv, &ssh_pub_content).unwrap();
    let private_key_doc = build_test_private_key(
        &private_key,
        &public_key.protected.subject_handle,
        &public_key.protected.kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();

    save_key_pair_atomic(
        &keystore_root,
        &public_key.protected.subject_handle,
        &public_key.protected.kid,
        &private_key_doc,
        &public_key,
    )
    .unwrap();

    set_active_kid(
        &public_key.protected.subject_handle,
        &public_key.protected.kid,
        &keystore_root,
    )
    .unwrap();

    let workspace_dir = temp_dir.path().join("workspace");
    let members_dir = workspace_dir.join("members/active");
    ensure_restricted_dir(&members_dir);
    ensure_restricted_dir(&workspace_dir.join("members/incoming"));
    ensure_restricted_dir(&workspace_dir.join("secrets"));
    let member_file = members_dir.join(format!("{}.json", member_handle));
    fs::write(
        &member_file,
        serde_json::to_string_pretty(&public_key).unwrap(),
    )
    .unwrap();

    temp_dir
}
