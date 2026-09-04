// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests the keystore read that takes the signer key one signature names.
//! Fixes which read failures keep the reset route and which travel as themselves.

use std::fs;

use crate::feature::trust::signer_keys::SignerKeySnapshot;
use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::{Kid, MemberHandle};
use crate::service::trust::recovery::{evaluate_trust_store_reset, TrustStoreResetCause};
use crate::test_utils::{setup_test_keystore_from_fixtures, ALICE_MEMBER_HANDLE};
use crate::ErrorKind;
use tempfile::TempDir;

use super::load_signer_key_snapshot;

struct SignerKeyFixture {
    home: TempDir,
    access: KeystoreAccess,
    owner: MemberHandle,
    kid: Kid,
}

impl SignerKeyFixture {
    fn open() -> Self {
        let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
        let access = KeystoreAccess::open(home.path().join("keys")).unwrap();
        let owner = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
        let kid = access
            .load_active_kid(&owner)
            .unwrap()
            .expect("the fixture keystore activates one key");
        Self {
            home,
            access,
            owner,
            kid,
        }
    }

    fn key_dir(&self) -> std::path::PathBuf {
        self.home
            .path()
            .join("keys")
            .join(ALICE_MEMBER_HANDLE)
            .join(self.kid.as_str())
    }

    fn load(&self) -> crate::Result<SignerKeySnapshot> {
        load_signer_key_snapshot(&self.access, &self.owner, Some(&self.kid))
    }
}

/// A key the keystore no longer holds is an absence, not a read failure. The
/// snapshot comes back empty and verification is what names the missing signer.
#[test]
fn test_absent_signer_key_document_is_loaded_as_no_key() {
    let fixture = SignerKeyFixture::open();
    fs::remove_file(fixture.key_dir().join("public.json")).unwrap();

    let snapshot = fixture.load().unwrap();

    assert!(snapshot.find(&fixture.kid).is_none());
}

/// A key document that will not read back leaves the stored signature
/// unverifiable, so it keeps the route that resets the store or restores the
/// key, and the message names that route before anything offers a deletion.
#[test]
fn test_unreadable_signer_key_document_keeps_the_reset_route() {
    let fixture = SignerKeyFixture::open();
    fs::write(fixture.key_dir().join("public.json"), "not-a-public-key").unwrap();

    let error = fixture
        .load()
        .expect_err("a key document that will not parse must be reported");

    assert_eq!(
        evaluate_trust_store_reset(&error),
        Some(TrustStoreResetCause::InvalidDocument)
    );
    let message = error.format_user_message();
    assert!(message.contains("trust resign"), "{message}");
    assert!(message.contains("public.json"), "{message}");
}

/// A read that never reached the document says nothing about it. Reporting it
/// as an unusable signer key would offer to discard every stored approval over
/// a permission that a `chmod` puts back.
#[cfg(unix)]
#[test]
fn test_signer_key_read_failure_travels_as_itself() {
    use crate::test_utils::permission_denial_can_be_staged;
    use std::os::unix::fs::PermissionsExt;
    if !permission_denial_can_be_staged("test_signer_key_read_failure_travels_as_itself") {
        return;
    }
    let fixture = SignerKeyFixture::open();
    let key_dir = fixture.key_dir();
    fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o000)).unwrap();

    let error = fixture
        .load()
        .expect_err("a key directory that cannot be opened must be reported");
    fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(evaluate_trust_store_reset(&error), None);
}

/// The snapshot holds a whole key document and the keystore root it came from,
/// and both are rendered wherever an enclosing type is formatted. Only the key
/// it found identifies it.
#[test]
fn test_snapshot_debug_output_names_the_key_only() {
    let fixture = SignerKeyFixture::open();

    let rendered = format!("{:?}", fixture.load().unwrap());

    assert!(rendered.contains(fixture.kid.as_str()), "{rendered}");
    assert!(!rendered.contains("subject_handle"), "{rendered}");
    assert!(!rendered.contains(&fixture.home.path().display().to_string()));
}
