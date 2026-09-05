// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for the signer key one trust store signature names.
//! Covers which signature kid names a key, and the route back when it is unusable.

use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::{TrustStoreDocument, TrustStoreProtected, TrustStoreSignature};
use crate::model::wire::algorithm::SIGNATURE_ED25519;
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use std::path::PathBuf;

use super::{build_signer_key_recovery_hint, document_signer_kid};

/// A stored key id, and the same one spelled the way it is shown to an
/// operator. A stored document never carries the second form.
const SIGNER_KID: &str = "KAD1AAAA1111BBBB2222CCCC3333DDDD";
const SIGNER_KID_DISPLAY_FORM: &str = "kad1-aaaa-1111-bbbb-2222-cccc-3333-dddd";
const STORED_AT: &str = "2026-03-29T12:34:56Z";

fn owner_handle() -> MemberHandle {
    MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap()
}

fn stored_signer_kid() -> Kid {
    Kid::from_canonical(SIGNER_KID.to_string()).unwrap()
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

/// The recovery hint names the complete document to restore, its trusted
/// source and permissions, and the command that re-signs it.
#[test]
fn test_signer_key_recovery_hint_names_the_whole_route() {
    let hint = build_signer_key_recovery_hint(
        &PathBuf::from("/home/alice/.kapsaro/keys"),
        &owner_handle(),
        &stored_signer_kid(),
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
    let keystore_root = PathBuf::from("/home/alice/.kapsaro/keys\nrogue");

    let hint =
        build_signer_key_recovery_hint(&keystore_root, &owner_handle(), &stored_signer_kid());

    assert!(hint.contains("keys\\nrogue"), "{hint}");
    assert!(!hint.contains('\n'), "{hint}");
}
