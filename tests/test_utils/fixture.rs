// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use super::keygen_helpers::{create_test_private_key, keygen_test};
use secretenv::io::keystore::active::set_active_kid;
use secretenv::io::keystore::storage::save_key_pair_atomic;
use secretenv::model::private_key::PrivateKey;
use secretenv::model::public_key::PublicKey;
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

fn create_dir_all_restricted(path: &Path) {
    fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn build_shared_fixture() -> SharedFixture {
    let temp_dir = TempDir::new().expect("Failed to create temp dir for fixture generation");
    let (ssh_priv, _ssh_pub, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&temp_dir);

    let ssh_private_key_bytes =
        fs::read(&ssh_priv).expect("Failed to read generated SSH private key");

    let mut members = HashMap::new();
    for member_id in ["alice@example.com", "bob@example.com"] {
        let (plaintext, public_key) = keygen_test(member_id, &ssh_priv, &ssh_pub_content)
            .expect("Failed to generate test key pair");
        let private_key = create_test_private_key(
            &plaintext,
            &public_key.protected.member_id,
            &public_key.protected.kid,
            &ssh_priv,
            &ssh_pub_content,
        )
        .expect("Failed to create test private key");

        let kid = public_key.protected.kid.clone();
        members.insert(
            member_id.to_string(),
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

/// Load the fixture SSH public key content
#[allow(dead_code)]
pub fn load_fixture_ssh_pubkey() -> String {
    SHARED_FIXTURE.ssh_public_key_content.clone()
}

/// Write SSH keypair from shared fixture into per-test TempDir
fn write_ssh_keys(temp_dir: &TempDir) -> (PathBuf, String) {
    let fixture = &*SHARED_FIXTURE;
    let ssh_dir = temp_dir.path().join(".ssh");
    create_dir_all_restricted(&ssh_dir);

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
    member_id: &str,
    keystore_root: &Path,
    workspace_keystore: Option<&Path>,
    members_dir: &Path,
) {
    let fixture = &*SHARED_FIXTURE;
    let member = fixture
        .members
        .get(member_id)
        .unwrap_or_else(|| panic!("No fixture for member: {}", member_id));

    save_key_pair_atomic(
        keystore_root,
        &member.public_key.protected.member_id,
        &member.public_key.protected.kid,
        &member.private_key,
        &member.public_key,
    )
    .unwrap();

    if let Some(ws_keystore) = workspace_keystore {
        save_public_key(
            ws_keystore,
            &member.public_key.protected.member_id,
            &member.public_key.protected.kid,
            &member.public_key,
        )
        .unwrap();
    }

    let member_file = members_dir.join(format!("{}.json", member_id));
    fs::write(
        &member_file,
        serde_json::to_string_pretty(&member.public_key).unwrap(),
    )
    .unwrap();
}

/// Setup test keystore from shared fixture (no ssh-keygen calls)
pub fn setup_test_keystore_from_fixtures(member_id: &str) -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    write_ssh_keys(&temp_dir);

    let keystore_root = temp_dir.path().join("keys");
    create_dir_all_restricted(&keystore_root);

    let member = SHARED_FIXTURE
        .members
        .get(member_id)
        .unwrap_or_else(|| panic!("No fixture for member: {}", member_id));

    let workspace_dir = temp_dir.path().join("workspace");
    let members_dir = workspace_dir.join("members/active");
    create_dir_all_restricted(&members_dir);
    create_dir_all_restricted(&workspace_dir.join("members/incoming"));
    create_dir_all_restricted(&workspace_dir.join("secrets"));

    install_fixture_member(member_id, &keystore_root, None, &members_dir);
    set_active_kid(member_id, &member.kid, &keystore_root).unwrap();

    temp_dir
}

/// Setup test workspace from shared fixture (no ssh-keygen calls)
pub fn setup_test_workspace_from_fixtures(member_ids: &[&str]) -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    write_ssh_keys(&temp_dir);

    let workspace_dir = temp_dir.path().join("workspace");
    let workspace_keystore = workspace_dir.join("keystore");
    let members_dir = workspace_dir.join("members/active");
    create_dir_all_restricted(&workspace_keystore);
    create_dir_all_restricted(&members_dir);
    create_dir_all_restricted(&workspace_dir.join("members/incoming"));
    create_dir_all_restricted(&workspace_dir.join("secrets"));

    let base_keystore = temp_dir.path().join("keys");
    create_dir_all_restricted(&base_keystore);

    for member_id in member_ids {
        install_fixture_member(
            member_id,
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
    member_id: &str,
    kid: &str,
    public_key: &secretenv::model::public_key::PublicKey,
) -> secretenv::Result<()> {
    let dir = keystore_root.join(member_id).join(kid);
    create_dir_all_restricted(&dir);
    secretenv::support::fs::atomic::save_json(&dir.join("public.json"), public_key)
}

/// Helper to create a temporary SSH Ed25519 keypair for testing
///
/// Returns: (private_key_path, public_key_path, public_key_content)
pub fn create_temp_ssh_keypair_in_dir(temp_dir: &TempDir) -> (PathBuf, PathBuf, String) {
    let ssh_dir = temp_dir.path().join(".ssh");
    create_dir_all_restricted(&ssh_dir);

    let private_key_path = ssh_dir.join("test_ed25519");
    let public_key_path = ssh_dir.join("test_ed25519.pub");

    let output = std::process::Command::new("ssh-keygen")
        .arg("-t")
        .arg(secretenv::io::ssh::protocol::constants::KEYGEN_TYPE_ED25519)
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
pub fn setup_test_workspace(member_ids: &[&str]) -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&temp_dir);

    let workspace_dir = temp_dir.path().join("workspace");
    let workspace_keystore = workspace_dir.join("keystore");
    let members_dir = workspace_dir.join("members/active");
    let secrets_dir = workspace_dir.join("secrets");
    create_dir_all_restricted(&workspace_keystore);
    create_dir_all_restricted(&members_dir);
    create_dir_all_restricted(&workspace_dir.join("members/incoming"));
    create_dir_all_restricted(&secrets_dir);

    let base_keystore = temp_dir.path().join("keys");
    create_dir_all_restricted(&base_keystore);

    for member_id in member_ids {
        let (private_key, public_key) =
            keygen_test(member_id, &ssh_priv, &ssh_pub_content).unwrap();
        let private_key_doc = create_test_private_key(
            &private_key,
            &public_key.protected.member_id,
            &public_key.protected.kid,
            &ssh_priv,
            &ssh_pub_content,
        )
        .unwrap();

        save_key_pair_atomic(
            &base_keystore,
            &public_key.protected.member_id,
            &public_key.protected.kid,
            &private_key_doc,
            &public_key,
        )
        .unwrap();

        set_active_kid(
            &public_key.protected.member_id,
            &public_key.protected.kid,
            &base_keystore,
        )
        .unwrap();

        save_public_key(
            &workspace_keystore,
            &public_key.protected.member_id,
            &public_key.protected.kid,
            &public_key,
        )
        .unwrap();

        let member_file = members_dir.join(format!("{}.json", member_id));
        fs::write(
            &member_file,
            serde_json::to_string_pretty(&public_key).unwrap(),
        )
        .unwrap();
    }

    // Write config.toml with the first member handle for auto-resolution
    if let Some(first_member_id) = member_ids.first() {
        let config_path = temp_dir.path().join("config.toml");
        fs::write(
            &config_path,
            format!("member_handle = \"{}\"\n", first_member_id),
        )
        .unwrap();
    }

    (temp_dir, workspace_dir)
}

/// Setup test environment with keystore and test keys
pub fn setup_test_keystore(member_id: &str) -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&temp_dir);

    let keystore_root = temp_dir.path().join("keys");
    create_dir_all_restricted(&keystore_root);

    let (private_key, public_key) = keygen_test(member_id, &ssh_priv, &ssh_pub_content).unwrap();
    let private_key_doc = create_test_private_key(
        &private_key,
        &public_key.protected.member_id,
        &public_key.protected.kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();

    save_key_pair_atomic(
        &keystore_root,
        &public_key.protected.member_id,
        &public_key.protected.kid,
        &private_key_doc,
        &public_key,
    )
    .unwrap();

    set_active_kid(
        &public_key.protected.member_id,
        &public_key.protected.kid,
        &keystore_root,
    )
    .unwrap();

    let workspace_dir = temp_dir.path().join("workspace");
    let members_dir = workspace_dir.join("members/active");
    create_dir_all_restricted(&members_dir);
    create_dir_all_restricted(&workspace_dir.join("members/incoming"));
    create_dir_all_restricted(&workspace_dir.join("secrets"));
    let member_file = members_dir.join(format!("{}.json", member_id));
    fs::write(
        &member_file,
        serde_json::to_string_pretty(&public_key).unwrap(),
    )
    .unwrap();

    temp_dir
}
