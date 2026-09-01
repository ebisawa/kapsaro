// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Active key state tests for the anchored keystore capability.
//! Covers canonical normalization and fail-closed reads of the active file.

use super::{parse_created_at, select_preferred_kid};
use crate::app_test_utils::{
    add_generated_key, build_test_private_key_document, build_test_public_key_document,
    TEST_KEY_CREATED_AT, TEST_KEY_EXPIRES_AT, TEST_KEY_SIGNATURE,
};
use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::{Kid, MemberHandle};
use crate::support::limits::MAX_ACTIVE_KID_FILE_SIZE;
use crate::test_utils::{
    create_local_state_dir, local_state_temp_dir, setup_test_keystore_from_fixtures,
    write_local_state_file, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};

const KID_A: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
const KID_B: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE";
const KID_C: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GF";
const EXPIRED_AT: &str = "2020-01-01T00:00:00Z";
const LATER_CREATED_AT: &str = "2024-06-01T00:00:00Z";
/// A timestamp of the shape the key document schema accepts that names no real
/// moment, so it reaches the timestamp readers and fails there.
const UNPARSABLE_TIMESTAMP: &str = "2024-13-01T00:00:00Z";
/// A key document cut off part way, the way an interrupted write leaves one.
const TRUNCATED_JSON_DOCUMENT: &str = "{\"protected\":{";

#[test]
fn test_set_and_load_active_kid() {
    let temp = local_state_temp_dir();
    let keystore_root = temp.path();
    let access = KeystoreAccess::create(keystore_root).unwrap();
    let member_handle = MemberHandle::try_from("alice@example.com").unwrap();
    let test_kid = Kid::try_from("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();

    access
        .set_active_kid_unchecked(&member_handle, &test_kid)
        .unwrap();
    let active = access.load_active_kid(&member_handle).unwrap();

    assert_eq!(active, Some(test_kid));
}

#[test]
fn test_load_active_kid_invalid_format() {
    let temp = local_state_temp_dir();
    let keystore_root = temp.path();
    let member_handle = MemberHandle::try_from("alice@example.com").unwrap();
    let invalid_kid = "invalid\n";

    let active_path = keystore_root.join(member_handle.as_str()).join("active");
    create_local_state_dir(active_path.parent().unwrap());
    write_local_state_file(&active_path, invalid_kid);

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let err = access.load_active_kid(&member_handle).unwrap_err();

    assert_eq!(err.kind(), crate::ErrorKind::InvalidArgument);
    assert!(err.to_string().contains("Crockford Base32"), "{err}");
}

/// A symlink named `active` stands where the keystore writes the marker, so it
/// is refused as shadowing rather than followed to whatever it names.
#[cfg(unix)]
#[test]
fn test_load_active_kid_rejects_active_named_symlink() {
    use std::os::unix::fs::symlink;

    let temp = local_state_temp_dir();
    let keystore_root = temp.path();
    let member_handle = MemberHandle::try_from("alice@example.com").unwrap();
    let active_path = keystore_root.join(member_handle.as_str()).join("active");
    let target = keystore_root.join("target-active");
    std::fs::create_dir_all(active_path.parent().unwrap()).unwrap();
    std::fs::write(&target, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD\n").unwrap();
    symlink(&target, &active_path).unwrap();

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let err = access.load_active_kid(&member_handle).unwrap_err();

    assert_eq!(err.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(err.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(err.to_string().contains("shadowing"), "{err}");
}

#[test]
fn test_load_active_kid_rejects_oversized_file() {
    let temp = local_state_temp_dir();
    let keystore_root = temp.path();
    let member_handle = MemberHandle::try_from("alice@example.com").unwrap();
    let active_path = keystore_root.join(member_handle.as_str()).join("active");
    std::fs::create_dir_all(active_path.parent().unwrap()).unwrap();
    std::fs::write(&active_path, "A".repeat(MAX_ACTIVE_KID_FILE_SIZE + 1)).unwrap();

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let err = access.load_active_kid(&member_handle).unwrap_err();

    assert_eq!(err.kind(), crate::ErrorKind::Parse);
    assert!(
        err.to_string().contains("exceeds maximum size limit"),
        "{err}"
    );
}

#[test]
fn test_set_active_kid_writes_canonical_typed_value() {
    let temp = local_state_temp_dir();
    let keystore_root = temp.path();
    let access = KeystoreAccess::create(keystore_root).unwrap();
    let member_handle = MemberHandle::try_from("alice@example.com").unwrap();
    let kid = Kid::try_from("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();

    access
        .set_active_kid_unchecked(&member_handle, &kid)
        .unwrap();

    let active = access.load_active_kid(&member_handle).unwrap();
    assert_eq!(
        active.as_ref().map(Kid::as_str),
        Some("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")
    );
}

/// An explicitly named key is answered with that key's public half, not with
/// the public half of whichever key the member currently has active. The key
/// named here is deliberately the one that is not active, so an implementation
/// falling back to the active key is caught.
#[test]
fn test_resolve_public_key_answers_the_named_key() {
    let temp = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp.path().join("keys");
    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let spare_kid = add_generated_key(temp.path(), ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(&keystore_root).unwrap();
    let active_kid = access.load_active_kid(&member_handle).unwrap().unwrap();
    assert_ne!(spare_kid, active_kid);

    let (kid, public_key) = access
        .resolve_public_key(&member_handle, Some(spare_kid.as_str()))
        .unwrap();

    assert_eq!(kid, spare_kid);
    assert_eq!(public_key.protected.kid, spare_kid.as_str());
}

/// Stage one key pair for a member with the validity window a test needs.
fn save_key(
    access: &KeystoreAccess,
    member: &MemberHandle,
    kid: &str,
    created_at: Option<&str>,
    expires_at: &str,
) -> Kid {
    let kid = Kid::try_from(kid).unwrap();
    let mut public_key =
        build_test_public_key_document(member.as_str(), kid.as_str(), TEST_KEY_SIGNATURE);
    public_key.protected.created_at = created_at.map(str::to_string);
    public_key.protected.expires_at = expires_at.to_string();
    access
        .save_key_pair_atomic(
            member,
            &kid,
            &build_test_private_key_document(member.as_str(), kid.as_str()),
            &public_key,
        )
        .unwrap();
    kid
}

fn key_document_path(
    keystore_root: &std::path::Path,
    member: &MemberHandle,
    kid: &Kid,
) -> std::path::PathBuf {
    keystore_root.join(member.as_str()).join(kid.as_str())
}

fn test_member() -> MemberHandle {
    MemberHandle::try_from("alice@example.com").unwrap()
}

/// Put `document` in place of the stored private half of one key, the way a
/// restore from the wrong backup or a hand-edited keystore would.
fn overwrite_private_key_document(
    keystore_root: &std::path::Path,
    member: &MemberHandle,
    kid: &Kid,
    document: &str,
) {
    write_local_state_file(
        &key_document_path(keystore_root, member, kid).join("private.json"),
        document,
    );
}

/// Serialize a private key document stating `member` and `kid`.
fn serialized_private_key_document(member: &str, kid: &str) -> String {
    serde_json::to_string_pretty(&build_test_private_key_document(member, kid)).unwrap()
}

/// The newest key wins, and the canonically first `kid` settles a tie.
#[test]
fn test_key_selection_prefers_the_newest_key_then_the_first_kid() {
    let older_kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    let preferred_newer_kid = Kid::try_from("00000000000000000000000000000001").unwrap();
    let other_newer_kid = Kid::try_from("00000000000000000000000000000002").unwrap();
    let created_at = time::OffsetDateTime::now_utc();
    let older_created_at = created_at - time::Duration::seconds(1);

    let selected = select_preferred_kid(vec![
        (older_kid, Some(older_created_at)),
        (other_newer_kid, Some(created_at)),
        (preferred_newer_kid.clone(), Some(created_at)),
    ]);

    assert_eq!(selected, Some(preferred_newer_kid));
}

/// `created_at` is optional in the signed statement, so a key omitting it is
/// still a candidate: it simply sorts behind every key that states one.
#[test]
fn test_key_selection_orders_a_key_without_created_at_last() {
    let timestamped_kid = Kid::try_from("00000000000000000000000000000001").unwrap();
    let undated_kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    let created_at = time::OffsetDateTime::now_utc() - time::Duration::days(3650);

    let selected = select_preferred_kid(vec![
        (undated_kid.clone(), None),
        (timestamped_kid.clone(), Some(created_at)),
    ]);
    let undated_only = select_preferred_kid(vec![(undated_kid.clone(), None)]);

    assert_eq!(selected, Some(timestamped_kid));
    assert_eq!(undated_only, Some(undated_kid));
}

/// A public key that omits `created_at` is read as stating no creation time.
#[test]
fn test_parse_created_at_reads_an_omitted_timestamp_as_absent() {
    let mut public_key =
        build_test_public_key_document("alice@example.com", KID_A, TEST_KEY_SIGNATURE);
    public_key.protected.created_at = None;

    assert_eq!(parse_created_at(&public_key).unwrap(), None);

    public_key.protected.created_at = Some(TEST_KEY_CREATED_AT.to_string());
    assert!(parse_created_at(&public_key).unwrap().is_some());
}

/// Resolving a key without an active marker falls back to the newest key, and
/// a key that omits `created_at` takes part in that instead of failing it.
#[test]
fn test_resolve_kid_without_an_active_marker_ranks_an_undated_key_last() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    save_key(&access, &member, KID_A, None, TEST_KEY_EXPIRES_AT);
    let dated_kid = save_key(
        &access,
        &member,
        KID_B,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );

    let resolved = access.resolve_kid(&member, None).unwrap();

    assert_eq!(resolved, dated_kid);
}

/// Activation without a named key takes the newest key that is still valid.
#[test]
fn test_activate_latest_valid_key_takes_the_newest_unexpired_key() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    let newest_kid = save_key(
        &access,
        &member,
        KID_B,
        Some(LATER_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );

    let activated = access.activate_latest_valid_key(&member).unwrap();

    assert_eq!(activated, newest_kid);
    assert_eq!(access.load_active_kid(&member).unwrap(), Some(newest_kid));
}

/// An expired key cannot be signed with, so activation passes it over even
/// though it is the newest key the member holds.
#[test]
fn test_activate_latest_valid_key_passes_over_an_expired_key() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let valid_kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    save_key(&access, &member, KID_B, Some(LATER_CREATED_AT), EXPIRED_AT);

    let activated = access.activate_latest_valid_key(&member).unwrap();

    assert_eq!(activated, valid_kid);
}

/// Every key of the member is expired, so there is nothing to activate and the
/// message says why rather than claiming the member has no keys.
#[test]
fn test_activate_latest_valid_key_reports_that_every_key_is_unusable() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        EXPIRED_AT,
    );

    let error = access.activate_latest_valid_key(&member).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
    assert!(error.to_string().contains("expired"), "{error}");
    assert_eq!(access.load_active_kid(&member).unwrap(), None);
}

/// A key whose private half is gone cannot be signed with, so activation picks
/// the next best key instead of naming it and failing at the write.
#[test]
fn test_activate_latest_valid_key_passes_over_a_key_without_its_private_half() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let complete_kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    let newest_kid = save_key(
        &access,
        &member,
        KID_C,
        Some(LATER_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    std::fs::remove_file(key_document_path(temp.path(), &member, &newest_kid).join("private.json"))
        .unwrap();

    let activated = access.activate_latest_valid_key(&member).unwrap();

    assert_eq!(activated, complete_kid);
}

/// Resolving a key nobody named walks the same keys activation walks, so a key
/// stored with only one half is passed over there too. One incomplete key
/// directory would otherwise hide every other key the member holds.
#[test]
fn test_resolve_kid_without_an_active_marker_passes_over_a_half_missing_key() {
    for missing_document in ["public.json", "private.json"] {
        let temp = local_state_temp_dir();
        let access = KeystoreAccess::create(temp.path()).unwrap();
        let member = test_member();
        let complete_kid = save_key(
            &access,
            &member,
            KID_A,
            Some(TEST_KEY_CREATED_AT),
            TEST_KEY_EXPIRES_AT,
        );
        let newest_kid = save_key(
            &access,
            &member,
            KID_B,
            Some(LATER_CREATED_AT),
            TEST_KEY_EXPIRES_AT,
        );
        std::fs::remove_file(
            key_document_path(temp.path(), &member, &newest_kid).join(missing_document),
        )
        .unwrap();

        let resolved = access.resolve_kid(&member, None).unwrap();

        assert_eq!(resolved, complete_kid, "missing {missing_document}");
    }
}

/// Every key the member holds is stored with one half missing. The key
/// directories are there, so the failure names them as local state to repair
/// instead of reporting a member that `key list` still shows keys for.
#[test]
fn test_resolve_kid_reports_keys_stored_with_one_half_missing() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    std::fs::remove_file(key_document_path(temp.path(), &member, &kid).join("public.json"))
        .unwrap();

    let error = access.resolve_kid(&member, None).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
    let message = error.format_user_message();
    assert!(
        message.contains("missing one of the two key documents"),
        "{message}"
    );
    assert!(message.contains(KID_A), "{message}");
}

/// Activation reports the same incomplete key the same way, so an operator who
/// meets it on either route is pointed at one repair.
#[test]
fn test_activate_latest_valid_key_names_a_key_stored_with_one_half_missing() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    std::fs::remove_file(key_document_path(temp.path(), &member, &kid).join("private.json"))
        .unwrap();

    let error = access.activate_latest_valid_key(&member).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
    let message = error.format_user_message();
    assert!(
        message.contains("missing one of the two key documents"),
        "{message}"
    );
    assert!(message.contains(KID_A), "{message}");
}

/// `key activate` is the repair the keystore names for a member left without an
/// active key, so a single key whose documents cannot be read must not take
/// that repair down with it.
#[test]
fn test_activate_latest_valid_key_passes_over_a_key_that_cannot_be_read() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let complete_kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    let newest_kid = save_key(
        &access,
        &member,
        KID_C,
        Some(LATER_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    write_local_state_file(
        &key_document_path(temp.path(), &member, &newest_kid).join("public.json"),
        TRUNCATED_JSON_DOCUMENT,
    );

    let activated = access.activate_latest_valid_key(&member).unwrap();

    assert_eq!(activated, complete_kid);
}

/// With nothing left to choose, the failure carries what stopped each key it
/// could not read, so the operator is told what to repair.
#[test]
fn test_activate_latest_valid_key_reports_a_key_that_cannot_be_read() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    write_local_state_file(
        &key_document_path(temp.path(), &member, &kid).join("public.json"),
        TRUNCATED_JSON_DOCUMENT,
    );

    let error = access.activate_latest_valid_key(&member).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
    assert!(error.to_string().contains("could not be read"), "{error}");
}

/// The active marker is unlinked first and its directory entry persisted after,
/// and the two failures ask for opposite repairs. A member directory that
/// cannot be written stops the unlink, so the marker stands where it stood and
/// the failure says exactly that.
#[cfg(unix)]
#[test]
fn test_remove_key_reports_an_active_marker_that_could_not_be_unlinked() {
    use std::os::unix::fs::PermissionsExt;

    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    access.activate_existing_key(&member, &kid).unwrap();
    let member_dir = temp.path().join(member.as_str());
    std::fs::set_permissions(&member_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

    let error = access
        .remove_key_with_validation(&member, &kid, |_| Ok(()))
        .unwrap_err();

    std::fs::set_permissions(&member_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(error.kind(), crate::ErrorKind::Io);
    assert!(
        error
            .format_user_message()
            .contains("still names the key it named before"),
        "{error}"
    );
    assert_eq!(access.load_active_kid(&member).unwrap(), Some(kid));
}

/// A named key still has to be usable. A marker on a key stored with one half
/// gone makes every later read of the member's active key report it as missing,
/// which takes that member's encryption and recipient resolution down.
///
/// The key directory is still there and `key list` still shows it, so naming
/// the key and what it lacks is what the refusal says, in the same words the
/// automatic selection uses for the same key.
#[test]
fn test_activate_existing_key_names_a_key_stored_with_one_half_missing() {
    for missing_document in ["public.json", "private.json"] {
        let temp = local_state_temp_dir();
        let access = KeystoreAccess::create(temp.path()).unwrap();
        let member = test_member();
        let kid = save_key(
            &access,
            &member,
            KID_A,
            Some(TEST_KEY_CREATED_AT),
            TEST_KEY_EXPIRES_AT,
        );
        std::fs::remove_file(key_document_path(temp.path(), &member, &kid).join(missing_document))
            .unwrap();

        let error = access.activate_existing_key(&member, &kid).unwrap_err();

        assert_eq!(
            error.kind(),
            crate::ErrorKind::InvalidOperation,
            "missing {missing_document}"
        );
        let message = error.format_user_message();
        assert!(
            message.contains("missing one of the two key documents"),
            "{message}"
        );
        assert!(message.contains(KID_A), "{message}");
        assert_eq!(access.load_active_kid(&member).unwrap(), None);
    }
}

/// An expired key is refused by every command that would use it, so naming it
/// is refused here too, with a message that says the key is there and spent
/// rather than reporting it as absent.
#[test]
fn test_activate_existing_key_refuses_an_expired_key() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        EXPIRED_AT,
    );

    let error = access.activate_existing_key(&member, &kid).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(error.to_string().contains("has expired"), "{error}");
    assert_eq!(access.load_active_kid(&member).unwrap(), None);
}

/// A key both halves are present for and that has not expired is activated.
#[test]
fn test_activate_existing_key_takes_a_complete_unexpired_key() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );

    access.activate_existing_key(&member, &kid).unwrap();

    assert_eq!(access.load_active_kid(&member).unwrap(), Some(kid));
}

/// The private half is what the member signs and decrypts with, so a document
/// that does not parse is not a key that can be made active. Deciding on the
/// file standing there would point the marker at a key every later command
/// fails on, with `key list` still showing it as the member's active key.
#[test]
fn test_activate_existing_key_refuses_a_private_half_that_does_not_parse() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    overwrite_private_key_document(temp.path(), &member, &kid, TRUNCATED_JSON_DOCUMENT);

    let error = access.activate_existing_key(&member, &kid).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Parse);
    assert!(error.to_string().contains("PrivateKey"), "{error}");
    assert_eq!(access.load_active_kid(&member).unwrap(), None);
}

/// A key is addressed by the directory holding it, so a private half stating
/// another member is not this member's key however well formed it is. Every
/// read of the pair refuses it, so activation refuses it too.
#[test]
fn test_activate_existing_key_refuses_a_private_half_stating_another_member() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    overwrite_private_key_document(
        temp.path(),
        &member,
        &kid,
        &serialized_private_key_document(BOB_MEMBER_HANDLE, KID_A),
    );

    let error = access.activate_existing_key(&member, &kid).unwrap_err();

    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(error.to_string().contains(BOB_MEMBER_HANDLE), "{error}");
    assert_eq!(access.load_active_kid(&member).unwrap(), None);
}

/// The key id is bound the same way the member handle is: a private half stating
/// a different key was not generated for the directory it stands in.
#[test]
fn test_activate_existing_key_refuses_a_private_half_stating_another_key() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    overwrite_private_key_document(
        temp.path(),
        &member,
        &kid,
        &serialized_private_key_document(member.as_str(), KID_B),
    );

    let error = access.activate_existing_key(&member, &kid).unwrap_err();

    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(error.to_string().contains(KID_B), "{error}");
    assert_eq!(access.load_active_kid(&member).unwrap(), None);
}

/// The two walks over a member's keys answer different questions, so they part
/// on a key whose private half will not parse.
///
/// Resolving a key nobody named picks which stored key a command reads, and the
/// public half of this one is intact, so it is answered with. Activation hands
/// the member a key to sign and decrypt with, so it passes the same key over
/// and takes the next best one. `key activate` is the repair for a member left
/// without an active key, so one unreadable key must not take that repair down
/// with it either.
#[test]
fn test_key_resolution_answers_the_newest_key_that_activation_passes_over() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let complete_kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    let newest_kid = save_key(
        &access,
        &member,
        KID_C,
        Some(LATER_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    overwrite_private_key_document(temp.path(), &member, &newest_kid, TRUNCATED_JSON_DOCUMENT);

    // Resolved before the activation, so the member still has no active marker
    // and the resolution walks the keys rather than reading the marker.
    let (resolved_kid, public_key) = access.resolve_public_key(&member, None).unwrap();
    let activated = access.activate_latest_valid_key(&member).unwrap();

    assert_eq!(resolved_kid, newest_kid);
    assert_eq!(public_key.protected.kid, newest_kid.as_str());
    assert_eq!(activated, complete_kid);
}

/// One key of the member that cannot be signed with is one key, not a fault of
/// the member. Resolving a key nobody named reaches the newest key past it
/// instead of failing on it, which would leave every command that resolves
/// without naming a key unusable until the old key was repaired or removed.
#[test]
fn test_resolve_public_key_reaches_the_newest_key_past_a_broken_private_half() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let broken_kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    let newest_kid = save_key(
        &access,
        &member,
        KID_C,
        Some(LATER_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    overwrite_private_key_document(temp.path(), &member, &broken_kid, TRUNCATED_JSON_DOCUMENT);

    let (resolved_kid, public_key) = access.resolve_public_key(&member, None).unwrap();

    assert_eq!(resolved_kid, newest_kid);
    assert_eq!(public_key.protected.kid, newest_kid.as_str());
}

/// A key whose private half states another member is ruled out as unreadable
/// rather than passed off as absent, so with nothing else to choose the failure
/// names what has to be repaired instead of calling the member keyless.
#[test]
fn test_activate_latest_valid_key_reports_a_private_half_stating_another_member() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        TEST_KEY_EXPIRES_AT,
    );
    overwrite_private_key_document(
        temp.path(),
        &member,
        &kid,
        &serialized_private_key_document(BOB_MEMBER_HANDLE, KID_A),
    );

    let error = access.activate_latest_valid_key(&member).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
    let message = error.format_user_message();
    assert!(message.contains("could not be read"), "{message}");
    assert!(message.contains(BOB_MEMBER_HANDLE), "{message}");
    assert_eq!(access.load_active_kid(&member).unwrap(), None);
}

/// A member holding no keys at all is told exactly that.
#[test]
fn test_activate_latest_valid_key_reports_a_member_holding_no_keys() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    access
        .set_active_kid_unchecked(&member, &Kid::try_from(KID_A).unwrap())
        .unwrap();

    let error = access.activate_latest_valid_key(&member).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
    assert!(error.to_string().contains("No keys found"), "{error}");
}

/// The marker is written canonical and key directories are listed canonical,
/// so a marker put there in display form by something else is refused.
#[test]
fn test_load_active_kid_requires_the_canonical_form() {
    let temp = local_state_temp_dir();
    let keystore_root = temp.path();
    let member = test_member();
    let active_path = keystore_root.join(member.as_str()).join("active");
    create_local_state_dir(active_path.parent().unwrap());
    write_local_state_file(&active_path, "7m2q-9d4r-1h8v-w6pk-t3xn-c5jy-2f9a-r8gd\n");

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let error = access.load_active_kid(&member).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
    assert!(
        error.to_string().contains("kid must be canonical"),
        "{error}"
    );
}

/// A marker holding nothing but whitespace names no key, so the member reads as
/// having no active key. Writing the marker empty is what an interrupted write
/// or a hand-edited keystore leaves behind.
#[test]
fn test_load_active_kid_reads_a_blank_marker_as_no_active_key() {
    for content in ["", "  \n"] {
        let temp = local_state_temp_dir();
        let keystore_root = temp.path();
        let member = test_member();
        let active_path = keystore_root.join(member.as_str()).join("active");
        create_local_state_dir(active_path.parent().unwrap());
        write_local_state_file(&active_path, content);

        let access = KeystoreAccess::open(keystore_root).unwrap();

        assert_eq!(access.load_active_kid(&member).unwrap(), None);
    }
}

/// A `created_at` the document validator accepts but no calendar holds is read
/// as an error rather than as a key stating no creation time: the document says
/// something it does not mean, and ordering it last would hide that.
#[test]
fn test_resolve_kid_reports_an_unparsable_created_at() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    save_key(
        &access,
        &member,
        KID_A,
        Some(UNPARSABLE_TIMESTAMP),
        TEST_KEY_EXPIRES_AT,
    );

    let error = access.resolve_kid(&member, None).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Parse);
    assert!(
        error
            .to_string()
            .contains(&format!("Invalid created_at format for key {KID_A}")),
        "{error}"
    );
}

/// Activation decides on the validity window, so an `expires_at` that cannot be
/// read as a moment in time stops it instead of being taken for either answer.
#[test]
fn test_activate_existing_key_reports_an_unparsable_expires_at() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path()).unwrap();
    let member = test_member();
    let kid = save_key(
        &access,
        &member,
        KID_A,
        Some(TEST_KEY_CREATED_AT),
        UNPARSABLE_TIMESTAMP,
    );

    let error = access.activate_existing_key(&member, &kid).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Parse);
    assert!(
        error
            .to_string()
            .contains(&format!("Invalid expires_at format for key {KID_A}")),
        "{error}"
    );
}
