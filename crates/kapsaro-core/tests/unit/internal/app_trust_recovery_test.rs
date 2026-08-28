// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Regression tests for invalid local trust store recovery.
//! Covers review-to-delete consistency and descriptor-bound path handling.

use crate::api::key::KeyContext;
use crate::app::context::crypto::load_crypto_context_with_access;
use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::list::{list_known_keys_command, resolve_trust_list_command};
use crate::app::trust::management::list_purge_candidates;
use crate::error::{LOCAL_KEYSTORE_MISSING_RECOVERY, TRUST_STORE_RESET_REQUIRED_RECOVERY};
use crate::io::keystore::access::KeystoreAccess;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::remove::{set_post_quarantine_hook, set_pre_quarantine_hook};
use crate::model::identity::MemberHandle;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::test_utils::ed25519_backend::Ed25519DirectBackend;
use crate::test_utils::{create_local_state_dir, member_handle, write_local_state_file};
use tempfile::TempDir;

use super::{
    build_trust_store_reset_plan_from_execution, build_trust_store_reset_plan_from_list_command,
    classify_trust_store_reset, execute_trust_store_reset,
    observe_trust_store_recovery_from_execution, observe_trust_store_recovery_from_list_command,
    TrustStoreResetPlan,
};

#[cfg(unix)]
use std::os::unix::fs::symlink;

fn build_options(home: &std::path::Path) -> CommonCommandOptions {
    CommonCommandOptions::new().with_home(Some(home.to_path_buf()))
}

/// A store whose bytes would not parse, reported the way a real load reports
/// it: still a parse failure, and naming a reset as the route past it.
fn build_reset_required_error() -> crate::Error {
    crate::Error::build_parse_error("Local trust store is invalid")
        .with_recovery(TRUST_STORE_RESET_REQUIRED_RECOVERY)
}

fn build_local_keystore_missing_error() -> crate::Error {
    crate::Error::build_local_keystore_missing_error("Local keystore is missing")
}

fn assert_local_keystore_missing_error(error: crate::Error) {
    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some(LOCAL_KEYSTORE_MISSING_RECOVERY));
    assert_eq!(error.format_user_message(), "Local keystore is missing");
}

/// Build a reset plan through the list command capability, the way `trust list`
/// recovery does, from a local state directory named by path.
fn build_reset_plan(
    home: &std::path::Path,
    error: crate::Error,
    is_interactive: bool,
) -> crate::Result<TrustStoreResetPlan> {
    let command =
        resolve_trust_list_command(&build_options(home), Some("alice@example.com".to_string()))?;
    let token = observe_trust_store_recovery_from_list_command(&command);
    build_trust_store_reset_plan_from_list_command(&command, token, error, is_interactive)
}

fn build_execution(home: &TempDir, member_handle: &str) -> ExecutionContext {
    let access = KeystoreAccess::open_from_home(home.path()).unwrap();
    let ssh_public_key =
        std::fs::read_to_string(home.path().join(".ssh/test_ed25519.pub")).unwrap();
    let backend = Ed25519DirectBackend::new(&home.path().join(".ssh/test_ed25519")).unwrap();
    let member_handle = MemberHandle::try_from(member_handle).unwrap();
    let key_ctx = load_crypto_context_with_access(
        access,
        member_handle.clone(),
        Box::new(backend),
        ssh_public_key,
        None,
        None,
    )
    .unwrap();
    ExecutionContext::from_test_parts(
        member_handle,
        KeyContext::from_inner(key_ctx),
        None,
        Some(home.path().to_path_buf()),
    )
    .unwrap()
}

#[test]
fn test_build_trust_store_reset_plan_resolves_delete_target() {
    let temp_dir = TempDir::new().unwrap();

    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();

    assert_eq!(
        plan.path(),
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"))
    );
    assert!(plan
        .warning_message()
        .contains("Local trust store is invalid"));
}

#[test]
fn test_execute_trust_store_reset_deletes_existing_target() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();

    let outcome = execute_trust_store_reset(&plan).unwrap();

    assert_eq!(outcome.path, trust_path);
    assert!(
        outcome.deleted,
        "an existing store must be reported deleted"
    );
    assert!(!outcome.path.exists());
}

#[test]
fn test_execute_trust_store_reset_allows_missing_target() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();

    let outcome = execute_trust_store_reset(&plan).unwrap();

    assert_eq!(outcome.path, trust_path);
    assert!(
        !outcome.deleted,
        "a store that was never there must not be reported deleted"
    );
    assert!(!outcome.path.exists());
}

/// A reset snapshot reads through the same bounded path as the trust store.
/// Refusing the plan leaves an oversized document in place for manual review.
#[test]
fn test_trust_store_reset_refuses_an_oversized_target() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    let file = std::fs::File::create(&trust_path).unwrap();
    file.set_len((MAX_JSON_DOCUMENT_READ_SIZE + 1) as u64)
        .unwrap();

    let error = build_reset_plan(temp_dir.path(), build_reset_required_error(), true)
        .expect_err("an oversized reset target must not be accepted for deletion");

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(
        error.format_user_message().contains("maximum size limit"),
        "{}",
        error.format_user_message()
    );
    assert!(
        trust_path.exists(),
        "the oversized document must be retained"
    );
}

#[test]
fn test_execute_trust_store_reset_preserves_atomically_replaced_target() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "invalid").unwrap();
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();
    let replacement = trust_path.with_extension("replacement");
    std::fs::write(&replacement, "valid-new").unwrap();
    std::fs::rename(replacement, &trust_path).unwrap();

    let error = execute_trust_store_reset(&plan).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(std::fs::read_to_string(trust_path).unwrap(), "valid-new");
}

#[test]
fn test_execute_trust_store_reset_preserves_modified_target() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "invalid").unwrap();
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();
    std::fs::write(&trust_path, "valid-new-content").unwrap();

    let error = execute_trust_store_reset(&plan).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(
        std::fs::read_to_string(trust_path).unwrap(),
        "valid-new-content"
    );
}

#[test]
fn test_execute_trust_store_reset_preserves_target_created_after_plan() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();
    std::fs::write(&trust_path, "valid-new").unwrap();

    let error = execute_trust_store_reset(&plan).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(std::fs::read_to_string(trust_path).unwrap(), "valid-new");
}

#[test]
fn test_build_trust_store_reset_plan_noninteractive_fails_without_deleting() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();

    let error = build_reset_plan(temp_dir.path(), build_reset_required_error(), false).unwrap_err();

    assert!(error.to_string().contains("non-interactive"));
    assert!(trust_path.exists());
}

#[test]
fn test_build_trust_store_reset_plan_preserves_unclassified_noninteractive_error() {
    let temp_dir = TempDir::new().unwrap();

    let error =
        build_reset_plan(temp_dir.path(), build_local_keystore_missing_error(), false).unwrap_err();

    assert_local_keystore_missing_error(error);
}

#[test]
fn test_list_command_reset_plan_preserves_unclassified_noninteractive_error() {
    let home = crate::test_utils::setup_test_keystore_from_fixtures("alice@example.com");
    let command = resolve_trust_list_command(&build_options(home.path()), None).unwrap();

    let token = observe_trust_store_recovery_from_list_command(&command);
    let error = build_trust_store_reset_plan_from_list_command(
        &command,
        token,
        build_local_keystore_missing_error(),
        false,
    )
    .unwrap_err();

    assert_local_keystore_missing_error(error);
}

#[test]
fn test_execution_reset_plan_preserves_unclassified_noninteractive_error() {
    let home = crate::test_utils::setup_test_keystore_from_fixtures("alice@example.com");
    let execution = build_execution(&home, "alice@example.com");

    let token = observe_trust_store_recovery_from_execution(&execution);
    let error = build_trust_store_reset_plan_from_execution(
        &execution,
        token,
        build_local_keystore_missing_error(),
        false,
    )
    .unwrap_err();

    assert_local_keystore_missing_error(error);
}

#[test]
fn test_trust_store_reset_ignores_unrelated_trust_entry() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "invalid").unwrap();
    let unrelated_path = trust_path.parent().unwrap().join("unexpected");
    std::fs::write(&unrelated_path, "stale").unwrap();

    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();
    execute_trust_store_reset(&plan).unwrap();

    assert!(!trust_path.exists());
    assert!(unrelated_path.exists());
}

#[cfg(unix)]
#[test]
fn test_execute_trust_store_reset_uses_opened_trust_directory_after_path_swap() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "invalid").unwrap();
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();
    let original_trust = temp_dir.path().join("trust.original");
    let outside = temp_dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let outside_target = outside.join("alice@example.com.json");
    std::fs::write(&outside_target, "outside").unwrap();
    std::fs::rename(temp_dir.path().join("trust"), &original_trust).unwrap();
    symlink(&outside, temp_dir.path().join("trust")).unwrap();

    execute_trust_store_reset(&plan).unwrap();

    assert!(!original_trust.join("alice@example.com.json").exists());
    assert_eq!(std::fs::read_to_string(outside_target).unwrap(), "outside");
}

#[cfg(unix)]
#[test]
fn test_build_trust_store_reset_plan_rejects_trust_directory_symlink() {
    let temp_dir = TempDir::new().unwrap();
    let outside = temp_dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    symlink(&outside, temp_dir.path().join("trust")).unwrap();

    let error = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
}

#[cfg(unix)]
#[test]
fn test_list_command_reset_uses_resolved_owner_and_trust_directory() {
    let home = crate::test_utils::setup_test_keystore_from_fixtures("alice@example.com");
    let alice_path = get_trust_store_file_path(home.path(), &member_handle("alice@example.com"));
    let bob_path = get_trust_store_file_path(home.path(), &member_handle("bob@example.com"));
    create_local_state_dir(alice_path.parent().unwrap());
    write_local_state_file(&alice_path, "invalid-alice");
    write_local_state_file(&bob_path, "invalid-bob");
    let options = build_options(home.path());
    let command = resolve_trust_list_command(&options, None).unwrap();
    let token = observe_trust_store_recovery_from_list_command(&command);
    let error = list_known_keys_command(&command).unwrap_err();
    let original_trust = home.path().join("trust.original");
    let replacement_trust = home.path().join("trust.replacement");
    create_local_state_dir(&replacement_trust);
    let replacement_alice = replacement_trust.join("alice@example.com.json");
    write_local_state_file(&replacement_alice, "replacement-alice");
    std::fs::rename(home.path().join("trust"), &original_trust).unwrap();
    std::fs::rename(&replacement_trust, home.path().join("trust")).unwrap();
    let plan =
        build_trust_store_reset_plan_from_list_command(&command, token, error, true).unwrap();

    execute_trust_store_reset(&plan).unwrap();

    assert!(!original_trust.join("alice@example.com.json").exists());
    assert_eq!(
        std::fs::read_to_string(original_trust.join("bob@example.com.json")).unwrap(),
        "invalid-bob"
    );
    assert_eq!(
        std::fs::read_to_string(home.path().join("trust/alice@example.com.json")).unwrap(),
        "replacement-alice"
    );
}

#[test]
fn test_list_command_reset_preserves_target_changed_after_plan() {
    let home = crate::test_utils::setup_test_keystore_from_fixtures("alice@example.com");
    let trust_path = get_trust_store_file_path(home.path(), &member_handle("alice@example.com"));
    create_local_state_dir(trust_path.parent().unwrap());
    write_local_state_file(&trust_path, "invalid");
    let command = resolve_trust_list_command(&build_options(home.path()), None).unwrap();
    let token = observe_trust_store_recovery_from_list_command(&command);
    let error = list_known_keys_command(&command).unwrap_err();
    let plan =
        build_trust_store_reset_plan_from_list_command(&command, token, error, true).unwrap();
    write_local_state_file(&trust_path, "replacement");

    let error = execute_trust_store_reset(&plan).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(std::fs::read_to_string(trust_path).unwrap(), "replacement");
}

/// The plan is bound to the document the failing run started from, so a store
/// replaced between that failure and the offer is reported as a conflict. The
/// operator is never shown one document's failure and asked to delete another.
#[test]
fn test_list_command_reset_plan_refuses_a_store_replaced_before_the_offer() {
    let home = crate::test_utils::setup_test_keystore_from_fixtures("alice@example.com");
    let trust_path = get_trust_store_file_path(home.path(), &member_handle("alice@example.com"));
    create_local_state_dir(trust_path.parent().unwrap());
    write_local_state_file(&trust_path, "invalid");
    let command = resolve_trust_list_command(&build_options(home.path()), None).unwrap();
    let token = observe_trust_store_recovery_from_list_command(&command);
    let error = list_known_keys_command(&command).unwrap_err();
    write_local_state_file(&trust_path, "replacement");

    let plan_error = build_trust_store_reset_plan_from_list_command(&command, token, error, true)
        .expect_err("a store replaced after the failure must not be offered for deletion");

    assert_eq!(plan_error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(
        plan_error
            .format_user_message()
            .contains("Run the command again"),
        "{}",
        plan_error.format_user_message()
    );
    assert_eq!(std::fs::read_to_string(&trust_path).unwrap(), "replacement");
}

/// A store whose signer key is merely missing holds intact approvals, so the
/// plan says how many of them the deletion would discard.
#[test]
fn test_reset_plan_counts_the_approvals_a_deletion_would_discard() {
    let home = crate::test_utils::setup_test_keystore_from_fixtures("alice@example.com");
    write_trust_store_with_absent_signer(&home, "alice@example.com", 2);
    let execution = build_execution(&home, "alice@example.com");
    let token = observe_trust_store_recovery_from_execution(&execution);
    let error = missing_signer_key_error(&execution);

    let plan = build_trust_store_reset_plan_from_execution(&execution, token, error, true).unwrap();

    let loss = plan
        .loss()
        .expect("a document that still parses must be countable");
    assert_eq!(loss.known_keys, 2);
    assert_eq!(loss.recipient_sets, 0);
}

/// Content that will not load names no number, so the plan reports none and
/// the operator is asked the plain question.
#[test]
fn test_reset_plan_reports_no_count_for_content_that_will_not_load() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "not-a-trust-store").unwrap();

    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();

    assert!(plan.loss().is_none());
}

#[cfg(unix)]
#[test]
fn test_execution_reset_deletes_only_original_home_target_after_path_swap() {
    let home = crate::test_utils::setup_test_keystore_from_fixtures("alice@example.com");
    let replacement = crate::test_utils::setup_test_keystore_from_fixtures("alice@example.com");
    let original_target =
        get_trust_store_file_path(home.path(), &member_handle("alice@example.com"));
    let replacement_target =
        get_trust_store_file_path(replacement.path(), &member_handle("alice@example.com"));
    create_local_state_dir(original_target.parent().unwrap());
    create_local_state_dir(replacement_target.parent().unwrap());
    write_local_state_file(&original_target, "invalid-original");
    write_local_state_file(&replacement_target, "replacement-bytes");
    let execution = build_execution(&home, "alice@example.com");
    let token = observe_trust_store_recovery_from_execution(&execution);
    let opened_home = home.path().with_extension("opened");
    std::fs::rename(home.path(), &opened_home).unwrap();
    std::fs::rename(replacement.path(), home.path()).unwrap();

    let error = list_purge_candidates(&execution, time::OffsetDateTime::now_utc()).unwrap_err();
    assert_eq!(error.recovery(), Some("E_TRUST_STORE_RESET_REQUIRED"));
    let opened_original_trust = opened_home.join("trust.original");
    std::fs::rename(opened_home.join("trust"), &opened_original_trust).unwrap();
    create_local_state_dir(&opened_home.join("trust"));
    let replaced_original_target =
        get_trust_store_file_path(&opened_home, &member_handle("alice@example.com"));
    write_local_state_file(&replaced_original_target, "replacement-directory-bytes");
    let plan = build_trust_store_reset_plan_from_execution(&execution, token, error, true).unwrap();
    execute_trust_store_reset(&plan).unwrap();

    let list_error =
        list_purge_candidates(&execution, time::OffsetDateTime::now_utc()).unwrap_err();
    assert_eq!(list_error.kind(), crate::ErrorKind::NotFound);

    assert!(!opened_original_trust
        .join("alice@example.com.json")
        .exists());
    assert_eq!(
        std::fs::read(&replaced_original_target).unwrap(),
        b"replacement-directory-bytes"
    );
    let home_target = get_trust_store_file_path(home.path(), &member_handle("alice@example.com"));
    assert_eq!(std::fs::read(home_target).unwrap(), b"replacement-bytes");
    drop(execution);
    std::fs::rename(home.path(), replacement.path()).unwrap();
    std::fs::rename(opened_home, home.path()).unwrap();
}

/// Write a trust store signed by a key that is absent from the local keystore,
/// reproducing the state left behind when the signing key is removed.
fn write_trust_store_with_absent_signer(
    home: &TempDir,
    owner: &str,
    known_key_count: usize,
) -> std::path::PathBuf {
    use crate::cli_api::test_support::storage::trust::store::save_trust_store;
    use crate::feature::trust::signature::sign_trust_store;
    use crate::model::trust_store::{KnownKey, KnownKeyApprovalVia, TrustStoreProtected};
    use crate::model::wire::format::LOCAL_TRUST_V1;

    let key_ctx = crate::test_utils::setup_member_key_context(home, owner, None);
    let known_keys = (0..known_key_count)
        .map(|_| KnownKey {
            kid: key_ctx.kid().to_string(),
            subject_handle: owner.to_string(),
            approved_at: "2026-03-29T12:34:56Z".to_string(),
            approved_via: KnownKeyApprovalVia::ManualReview,
            evidence: None,
            extra: Default::default(),
        })
        .collect();
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: owner.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys,
        recipient_sets: Vec::new(),
    };
    let mut document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    document.signature.kid = swap_first_kid_character(&document.signature.kid);
    let path = get_trust_store_file_path(home.path(), &member_handle(owner));
    save_trust_store(&path, &document).unwrap();
    path
}

/// Produce a syntactically valid kid that no keystore entry can match.
fn swap_first_kid_character(kid: &str) -> String {
    let replacement = if kid.starts_with('A') { 'B' } else { 'A' };
    format!("{replacement}{}", &kid[1..])
}

fn missing_signer_key_error(execution: &ExecutionContext) -> crate::Error {
    let error = list_purge_candidates(execution, time::OffsetDateTime::now_utc())
        .expect_err("an absent signer key must fail verification");
    assert_eq!(error.recovery(), Some("E_TRUST_SIGNER_KEY_MISSING"));
    error
}

#[test]
fn test_execute_trust_store_reset_deletes_a_store_whose_signer_key_is_absent() {
    let home = crate::test_utils::setup_test_keystore_from_fixtures("alice@example.com");
    let path = write_trust_store_with_absent_signer(&home, "alice@example.com", 1);
    let execution = build_execution(&home, "alice@example.com");
    let token = observe_trust_store_recovery_from_execution(&execution);
    let error = missing_signer_key_error(&execution);

    let plan = build_trust_store_reset_plan_from_execution(&execution, token, error, true).unwrap();
    let outcome = execute_trust_store_reset(&plan).unwrap();

    assert_eq!(outcome.path, path);
    assert!(!path.exists());
    let candidates = list_purge_candidates(&execution, time::OffsetDateTime::now_utc())
        .expect_err("an absent trust store leaves no purge candidates to review");
    assert_eq!(candidates.kind(), crate::ErrorKind::NotFound);
}

/// A read that could not tell whether the store still matches says nothing
/// about which document stands there. Reporting it as a conflict would tell the
/// operator the store moved when all that happened was a refused permission.
#[cfg(unix)]
#[test]
fn test_reset_plan_reports_a_read_failure_as_itself() {
    use crate::test_utils::permission_denial_can_be_staged;
    use std::os::unix::fs::PermissionsExt;
    if !permission_denial_can_be_staged("test_reset_plan_reports_a_read_failure_as_itself") {
        return;
    }
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "invalid").unwrap();
    let command = resolve_trust_list_command(
        &build_options(temp_dir.path()),
        Some("alice@example.com".to_string()),
    )
    .unwrap();
    let token = observe_trust_store_recovery_from_list_command(&command);
    std::fs::set_permissions(&trust_path, std::fs::Permissions::from_mode(0o000)).unwrap();

    let error = build_trust_store_reset_plan_from_list_command(
        &command,
        token,
        build_reset_required_error(),
        true,
    )
    .expect_err("a store that cannot be read must not be offered for deletion");
    std::fs::set_permissions(&trust_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert_eq!(error.kind(), crate::ErrorKind::Io);
    assert!(
        !error
            .format_user_message()
            .contains("Run the command again"),
        "{}",
        error.format_user_message()
    );
}

/// A store whose signer key is unavailable holds approvals that are intact, so
/// the route that keeps them travels with the plan and is put in front of the
/// operator where they are asked to discard them.
#[test]
fn test_reset_plan_carries_the_recovery_route_for_a_missing_signer_key() {
    let home = crate::test_utils::setup_test_keystore_from_fixtures("alice@example.com");
    write_trust_store_with_absent_signer(&home, "alice@example.com", 1);
    let execution = build_execution(&home, "alice@example.com");
    let token = observe_trust_store_recovery_from_execution(&execution);
    let error = missing_signer_key_error(&execution);

    let plan = build_trust_store_reset_plan_from_execution(&execution, token, error, true).unwrap();

    let hint = plan
        .recovery_hint()
        .expect("a missing signer key is repaired by putting the key back");
    assert!(
        hint.contains("kapsaro trust resign --member-handle alice@example.com"),
        "{hint}"
    );
}

/// Content that will not verify has no route back, so nothing is offered.
#[test]
fn test_reset_plan_offers_no_recovery_route_for_invalid_content() {
    let temp_dir = TempDir::new().unwrap();

    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();

    assert!(plan.recovery_hint().is_none());
}

/// Put a different document at the store's name, the way a writer that ignores
/// the directory lock would.
fn replace_stored_trust_document(trust_path: &std::path::Path, content: &str) {
    let staged = trust_path.with_extension("replacement");
    std::fs::write(&staged, content).unwrap();
    std::fs::rename(staged, trust_path).unwrap();
}

/// The single entry the reset moved aside and left under a name of its own.
fn read_moved_aside_entry(trust_dir: &std::path::Path) -> std::path::PathBuf {
    let mut moved: Vec<std::path::PathBuf> = std::fs::read_dir(trust_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".alice@example.com.json.tmp."))
        })
        .collect();
    assert_eq!(moved.len(), 1, "{moved:?}");
    moved.remove(0)
}

/// A document that arrives at the store's name after the confirmation survives.
///
/// The unlink names a directory entry rather than an inode, so the reset moves
/// the confirmed document aside and identifies what the move took. A document
/// that replaced it goes back under the name it came from, and the approvals it
/// holds outlive a reset that was aimed at another document entirely.
#[test]
fn test_execute_trust_store_reset_restores_a_store_replaced_before_the_deletion() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "invalid").unwrap();
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();
    let replaced = trust_path.clone();
    set_pre_quarantine_hook(move || replace_stored_trust_document(&replaced, "valid-new"));

    let error = execute_trust_store_reset(&plan).unwrap_err();

    let message = error.format_user_message();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(message.contains("nothing was deleted"), "{message}");
    assert_eq!(std::fs::read_to_string(&trust_path).unwrap(), "valid-new");
    let entries: Vec<String> = std::fs::read_dir(trust_path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec!["alice@example.com.json".to_string()]);
}

/// A name that stops holding a regular file is reported, not deleted.
///
/// The move takes whatever stands at the name, and only a regular file can be
/// identified against the descriptor the confirmation holds. Anything else ends
/// the reset and goes back where it was.
#[test]
fn test_execute_trust_store_reset_restores_a_name_that_stopped_being_a_file() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "invalid").unwrap();
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();
    let replaced = trust_path.clone();
    set_pre_quarantine_hook(move || {
        std::fs::remove_file(&replaced).unwrap();
        std::fs::create_dir(&replaced).unwrap();
    });

    let error = execute_trust_store_reset(&plan).unwrap_err();

    let message = error.format_user_message();
    assert!(message.contains("could not be identified"), "{message}");
    assert!(message.contains("nothing was deleted"), "{message}");
    assert!(trust_path.is_dir(), "the entry must be put back as it was");
}

/// A document the reset never confirmed is kept even when it cannot go back.
///
/// The move finds a document the confirmation never accepted, and the name it
/// came from is taken again before it can be returned. Nothing is deleted: the
/// document stays under the name the reset moved it to, and the report gives
/// both that name and the one it belongs under, so the operator can restore it.
#[test]
fn test_execute_trust_store_reset_keeps_a_document_it_cannot_put_back() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "invalid").unwrap();
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();
    let replaced = trust_path.clone();
    set_pre_quarantine_hook(move || replace_stored_trust_document(&replaced, "first-arrival"));
    let retaken = trust_path.clone();
    set_post_quarantine_hook(move || std::fs::write(&retaken, "second-arrival").unwrap());

    let error = execute_trust_store_reset(&plan).unwrap_err();

    let message = error.format_user_message();
    assert_eq!(error.kind(), crate::ErrorKind::Io);
    assert!(message.contains("was not deleted"), "{message}");
    assert!(
        message.contains("must be renamed to 'alice@example.com.json'"),
        "{message}"
    );
    let moved_aside = read_moved_aside_entry(trust_path.parent().unwrap());
    assert_eq!(
        std::fs::read_to_string(moved_aside).unwrap(),
        "first-arrival"
    );
    assert_eq!(
        std::fs::read_to_string(&trust_path).unwrap(),
        "second-arrival"
    );
}

/// Identity alone is insufficient after quarantine because a writer may keep
/// the inode open and rewrite it. The changed bytes are restored, not deleted.
#[test]
fn test_execute_trust_store_reset_restores_content_changed_after_quarantine() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "invalid").unwrap();
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();
    let trust_dir = trust_path.parent().unwrap().to_path_buf();
    set_post_quarantine_hook(move || {
        let quarantined = read_moved_aside_entry(&trust_dir);
        std::fs::write(quarantined, "changed-after-quarantine").unwrap();
    });

    let error = execute_trust_store_reset(&plan).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(
        std::fs::read_to_string(&trust_path).unwrap(),
        "changed-after-quarantine"
    );
    assert_eq!(
        std::fs::read_dir(trust_path.parent().unwrap())
            .unwrap()
            .count(),
        1
    );
}

/// A reset that ran leaves a trust directory the next command can still use.
///
/// The deletion moves the document aside before unlinking it, and an entry left
/// under that name would make every later trust operation refuse the directory
/// it sits in.
#[test]
fn test_execute_trust_store_reset_leaves_the_trust_directory_usable() {
    let temp_dir = TempDir::new().unwrap();
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle("alice@example.com"));
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, "{}").unwrap();
    let plan = build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();

    let outcome = execute_trust_store_reset(&plan).unwrap();

    assert!(outcome.deleted);
    build_reset_plan(temp_dir.path(), build_reset_required_error(), true).unwrap();
}

#[test]
fn test_classify_trust_store_reset_ignores_a_coded_operation_error() {
    let error = crate::Error::build_local_state_path_unsafe_error("unsafe local state".to_string());

    assert!(classify_trust_store_reset(&error).is_none());
}
