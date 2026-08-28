// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for the signer key one trust store signature names.
//! Fixes which read failures keep the reset route and which travel as themselves.

use std::fs;

use crate::app::trust::recovery::{classify_trust_store_reset, TrustStoreResetCause};
use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::{TrustStoreDocument, TrustStoreProtected, TrustStoreSignature};
use crate::model::wire::algorithm::SIGNATURE_ED25519;
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::test_utils::{setup_test_keystore_from_fixtures, ALICE_MEMBER_HANDLE};
use crate::ErrorKind;
use tempfile::TempDir;

use super::{build_signer_key_recovery_hint, document_signer_kid, SignerKeySnapshot};

/// A stored key id, and the same one spelled the way it is shown to an
/// operator. A stored document never carries the second form.
const SIGNER_KID: &str = "KAD1AAAA1111BBBB2222CCCC3333DDDD";
const SIGNER_KID_DISPLAY_FORM: &str = "kad1-aaaa-1111-bbbb-2222-cccc-3333-dddd";
const STORED_AT: &str = "2026-03-29T12:34:56Z";

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

    fn capture(&self) -> crate::Result<SignerKeySnapshot> {
        SignerKeySnapshot::capture(&self.access, &self.owner, Some(&self.kid))
    }
}

fn signed_trust_store_document(signature_kid: &str) -> TrustStoreDocument {
    TrustStoreDocument {
        protected: TrustStoreProtected {
            format: LOCAL_TRUST_V1.to_string(),
            owner_handle: ALICE_MEMBER_HANDLE.to_string(),
            created_at: STORED_AT.to_string(),
            updated_at: STORED_AT.to_string(),
            known_keys: Vec::new(),
            recipient_sets: Vec::new(),
        },
        signature: TrustStoreSignature {
            alg: SIGNATURE_ED25519.to_string(),
            kid: signature_kid.to_string(),
            sig: String::new(),
        },
    }
}

#[test]
fn test_canonical_signature_kid_names_the_signer_key() {
    let doc = signed_trust_store_document(SIGNER_KID);

    let kid = document_signer_kid(&doc).expect("a canonical signature kid names a key");

    assert_eq!(kid.as_str(), SIGNER_KID);
}

/// The key id is read as the canonical form a stored document carries. A
/// display form names no key at all, so the keystore is never searched under a
/// name the signed bytes never held, and verification is what reports the
/// document.
#[test]
fn test_display_form_signature_kid_names_no_signer_key() {
    let doc = signed_trust_store_document(SIGNER_KID_DISPLAY_FORM);

    assert!(document_signer_kid(&doc).is_none());
}

/// A key the keystore no longer holds is an absence, not a read failure. The
/// snapshot comes back empty and verification is what names the missing signer.
#[test]
fn test_absent_signer_key_document_is_captured_as_no_key() {
    let fixture = SignerKeyFixture::open();
    fs::remove_file(fixture.key_dir().join("public.json")).unwrap();

    let snapshot = fixture.capture().unwrap();

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
        .capture()
        .expect_err("a key document that will not parse must be reported");

    assert_eq!(
        classify_trust_store_reset(&error),
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
        .capture()
        .expect_err("a key directory that cannot be opened must be reported");
    fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(classify_trust_store_reset(&error), None);
}

/// The recovery hint names the complete document to restore, its trusted
/// source and permissions, and the command that re-signs it.
#[test]
fn test_signer_key_recovery_hint_names_the_whole_route() {
    let fixture = SignerKeyFixture::open();

    let hint = build_signer_key_recovery_hint(
        &fixture.home.path().join("keys"),
        &fixture.owner,
        &fixture.kid,
    );

    assert!(hint.contains("public.json"), "{hint}");
    assert!(hint.contains("trusted backup or known-good copy"), "{hint}");
    assert!(hint.contains("complete original document"), "{hint}");
    assert!(hint.contains("owner-only permissions"), "{hint}");
    assert!(
        hint.contains("kapsaro trust resign --member-handle alice@example.com"),
        "{hint}"
    );
    assert!(hint.contains("reset the trust store"), "{hint}");
    assert!(hint.contains("review the approvals again"), "{hint}");
    assert!(!hint.contains("kapsaro key export"), "{hint}");
}

/// The keystore root reaches the hint from configuration, so a newline in one
/// would end the line the hint sits on and let the rest read as a report of its
/// own. It is spelled out where the reader can see it.
#[test]
fn test_signer_key_recovery_hint_spells_out_a_control_character_in_the_path() {
    let fixture = SignerKeyFixture::open();
    let keystore_root = fixture.home.path().join("keys\nrogue");

    let hint = build_signer_key_recovery_hint(&keystore_root, &fixture.owner, &fixture.kid);

    assert!(hint.contains("keys\\nrogue"), "{hint}");
    assert!(!hint.contains('\n'), "{hint}");
}

/// The snapshot holds a whole key document and the keystore root it came from,
/// and both are rendered wherever an enclosing type is formatted. Only the key
/// it found identifies it.
#[test]
fn test_snapshot_debug_output_names_the_key_only() {
    let fixture = SignerKeyFixture::open();

    let rendered = format!("{:?}", fixture.capture().unwrap());

    assert!(rendered.contains(fixture.kid.as_str()), "{rendered}");
    assert!(!rendered.contains("subject_handle"), "{rendered}");
    assert!(!rendered.contains(&fixture.home.path().display().to_string()));
}
