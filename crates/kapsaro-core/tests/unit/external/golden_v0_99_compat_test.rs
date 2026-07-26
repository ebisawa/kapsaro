// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Backward compatibility checks against artifacts recorded by kapsaro 0.99.
//! Verifies and decrypts the stored files through the stable facade API.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use kapsaro_core::api::file::FileEncArtifact;
use kapsaro_core::api::key::{KeyContext, KeyContextOptions, LocalKeyStore};
use kapsaro_core::api::kv::KvEncArtifact;
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::ssh::{SshRawSignature, SshSignatureBackend};
use kapsaro_core::Result;
use serde_json::Value;
use tempfile::TempDir;

use crate::test_utils::ed25519_backend::Ed25519DirectBackend;

const FIXTURE_FILES: &[&str] = &[
    "expected.json",
    "file_enc.json",
    "id_ed25519",
    "id_ed25519.pub",
    "kv_enc.kvenc",
    "private.json",
    "public.json",
];

/// Bridges the recorded SSH key into the facade signing trait.
struct GoldenSshBackend {
    inner: Ed25519DirectBackend,
}

impl SshSignatureBackend for GoldenSshBackend {
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<SshRawSignature> {
        use kapsaro_core::cli_api::test_support::storage::ssh::backend::SignatureBackend;

        self.inner
            .sign_sshsig(namespace, ssh_pubkey, message)
            .map(|signature| SshRawSignature::new(*signature.as_bytes()))
    }
}

#[test]
fn test_golden_fixture_files_are_present() {
    for name in FIXTURE_FILES {
        let path = fixture_dir().join(name);
        assert!(path.is_file(), "missing golden fixture file: {name}");
    }
}

#[test]
fn test_golden_file_enc_verifies_and_decrypts() {
    let staged = stage_keystore();
    let key_ctx = load_golden_key_context(&staged);
    let expected = load_expected();

    let artifact = FileEncArtifact::load(fixture_dir().join("file_enc.json")).unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let plaintext = verified
        .decrypt_bytes(&key_ctx, OperationOptions::default())
        .unwrap();

    assert_eq!(
        plaintext.expose_secret(),
        expected_str(&expected, "file_enc_plaintext").as_bytes()
    );
}

#[test]
fn test_golden_kv_enc_verifies_and_decrypts() {
    let staged = stage_keystore();
    let key_ctx = load_golden_key_context(&staged);
    let expected = load_expected();

    let artifact = KvEncArtifact::load(fixture_dir().join("kv_enc.kvenc")).unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let entries = verified
        .decrypt_entries(&key_ctx, OperationOptions::default())
        .unwrap();

    let decrypted = entries
        .iter()
        .map(|(key, value)| (key.clone(), value.expose_secret().to_owned()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(decrypted, expected_kv_entries(&expected));
}

/// The facade verifies the embedded signer public key, and that check
/// re-derives `kid` from the signed `protected` object. A change to the
/// derivation therefore fails verification before this assertion runs.
#[test]
fn test_golden_key_context_resolves_the_recorded_kid() {
    let staged = stage_keystore();
    let key_ctx = load_golden_key_context(&staged);
    let expected = load_expected();

    assert_eq!(key_ctx.kid(), expected_str(&expected, "kid"));
    assert_eq!(
        key_ctx.member_handle(),
        expected_str(&expected, "member_handle")
    );
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("golden")
        .join("v0.99")
}

fn load_expected() -> Value {
    serde_json::from_str(&fs::read_to_string(fixture_dir().join("expected.json")).unwrap()).unwrap()
}

fn expected_str(expected: &Value, key: &str) -> String {
    expected[key].as_str().unwrap().to_owned()
}

fn expected_kv_entries(expected: &Value) -> BTreeMap<String, String> {
    expected["kv_entries"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
        .collect()
}

/// Copy the recorded keystore into a temporary directory with owner-only modes.
///
/// Git stores no permission bits beyond the executable flag, so the checked-out
/// fixtures are world-readable and would be rejected by keystore loading.
fn stage_keystore() -> TempDir {
    let expected = load_expected();
    let handle = expected_str(&expected, "member_handle");
    let kid = expected_str(&expected, "kid");
    let temp = TempDir::new().unwrap();

    let key_dir = temp.path().join("keys").join(&handle).join(&kid);
    copy_restricted(
        &fixture_dir().join("private.json"),
        &key_dir,
        "private.json",
    );
    copy_restricted(&fixture_dir().join("public.json"), &key_dir, "public.json");
    write_restricted(&temp.path().join("keys").join(&handle), "active", &kid);
    copy_restricted(
        &fixture_dir().join("id_ed25519"),
        &temp.path().join("ssh"),
        "id_ed25519",
    );
    restrict_dirs(temp.path());

    temp
}

fn copy_restricted(source: &Path, dir: &Path, name: &str) {
    write_restricted(dir, name, &fs::read_to_string(source).unwrap());
}

fn write_restricted(dir: &Path, name: &str, contents: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(dir).unwrap();
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Keystore loading walks the ancestor chain from the keystore root down, so
/// every staged directory has to be owner-only. Bounded to the staging tree.
fn restrict_dirs(root: &Path) {
    use std::os::unix::fs::PermissionsExt;

    for entry in fs::read_dir(root)
        .unwrap()
        .filter_map(std::result::Result::ok)
    {
        if entry.path().is_dir() {
            restrict_dirs(&entry.path());
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
}

fn load_golden_key_context(staged: &TempDir) -> KeyContext {
    let expected = load_expected();
    let ssh_pubkey = fs::read_to_string(fixture_dir().join("id_ed25519.pub"))
        .unwrap()
        .trim()
        .to_owned();
    let backend = GoldenSshBackend {
        inner: Ed25519DirectBackend::new(&staged.path().join("ssh").join("id_ed25519")).unwrap(),
    };

    LocalKeyStore::new(staged.path().join("keys"))
        .load_key_context(KeyContextOptions::new(
            expected_str(&expected, "member_handle"),
            Box::new(backend),
            ssh_pubkey,
        ))
        .unwrap()
}
