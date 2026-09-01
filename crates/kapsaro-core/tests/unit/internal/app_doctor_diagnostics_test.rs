// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::app::doctor::ci::check_ci_readiness;
use crate::app::doctor::local_state::set_post_keystore_open_hook;
use crate::app::doctor::types::{DoctorCheck, DoctorReason, DoctorStatus, DoctorSubject};
use crate::app::doctor::{execute_doctor_command, DoctorRequest};
use crate::cli_api::test_support::storage::keystore::active::set_active_kid;
use crate::cli_api::test_support::storage::keystore::storage::{list_kids, load_public_key};
use crate::cli_api::test_support::storage::trust::store::save_trust_store;
use crate::feature::context::crypto::SigningContext;
use crate::feature::kv::encrypt::encrypt_kv_map_with_wrap_mutation;
use crate::feature::trust::signature::sign_trust_store;
use crate::format::token::TokenCodec;
use crate::io::keystore::paths::{
    get_private_key_file_path_from_root, get_public_key_file_path_from_root,
};
use crate::io::trust::paths::get_trust_store_file_path;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::TrustStoreProtected;
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    create_local_state_dir, local_state_temp_dir, member_handle, permission_denial_can_be_staged,
    setup_member_key_context, setup_test_workspace_from_fixtures, write_local_state_file, EnvGuard,
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use tempfile::TempDir;

fn doctor_request(home: &TempDir, workspace: &Path) -> DoctorRequest {
    DoctorRequest {
        workspace: Some(workspace.to_path_buf()),
        home: Some(home.path().to_path_buf()),
        member_handle: Some(ALICE_MEMBER_HANDLE.to_string()),
        verbose: false,
    }
}

fn run_workspace_doctor(home: &TempDir, workspace: &Path) -> Vec<DoctorCheck> {
    execute_doctor_command(doctor_request(home, workspace))
        .unwrap()
        .checks()
        .to_vec()
}

fn has_check(checks: &[DoctorCheck], id: &str, status: DoctorStatus) -> bool {
    checks
        .iter()
        .any(|check| check.id == id && check.status == status)
}

/// Whether the report judged this at all, whatever the verdict was.
fn has_check_id(checks: &[DoctorCheck], id: &str) -> bool {
    checks.iter().any(|check| check.id == id)
}

fn find_check<'a>(checks: &'a [DoctorCheck], id: &str, status: DoctorStatus) -> &'a DoctorCheck {
    checks
        .iter()
        .find(|check| check.id == id && check.status == status)
        .unwrap_or_else(|| {
            panic!("doctor check not found: id={id}, status={status:?}, {checks:#?}")
        })
}

fn assert_trust_store_corruption_check(checks: &[DoctorCheck]) {
    let check = find_check(checks, "trust_store.integrity", DoctorStatus::Fail);

    assert_eq!(check.message, "Local trust store is invalid");
    assert_eq!(
        check.next_action.as_deref(),
        Some("follow the trust store recovery procedure")
    );
}

fn create_workspace_dirs(workspace: &Path) {
    fs::create_dir_all(workspace.join("members/active")).unwrap();
    fs::create_dir_all(workspace.join("members/incoming")).unwrap();
    fs::create_dir_all(workspace.join("secrets")).unwrap();
}

fn save_empty_trust_store(home: &TempDir) {
    let key_ctx = setup_member_key_context(home, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-05-10T00:00:00Z".to_string(),
        updated_at: "2026-05-10T00:00:00Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    save_trust_store(&path, &document).unwrap();
}

fn encrypted_kv_for_alice_only(home: &TempDir) -> String {
    encrypted_kv_for_recipients(home, ALICE_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE])
}

fn encrypted_kv_for_recipients(
    home: &TempDir,
    signer_handle: &str,
    recipient_handles: &[&str],
) -> String {
    let keystore_root = home.path().join("keys");
    let kid = list_kids(&keystore_root, signer_handle)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let signer_pub = load_public_key(&keystore_root, signer_handle, &kid).unwrap();
    let key_ctx = setup_member_key_context(home, signer_handle, Some(&kid));
    let recipients = recipient_handles
        .iter()
        .map(|handle| {
            let kid = list_kids(&keystore_root, handle)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            load_public_key(&keystore_root, handle, &kid).unwrap()
        })
        .collect::<Vec<_>>();
    let verified_members = build_verified_recipient_keys(&recipients);
    let mut values = HashMap::new();
    values.insert("API_TOKEN".to_string(), "secret".to_string());
    let signing = SigningContext {
        signing_key: key_ctx.signing_key(),
        signer_kid: &kid,
        signer_pub,
    };
    encrypt_kv_map_with_wrap_mutation(
        &values,
        &verified_members,
        &signing,
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap()
}

fn encrypted_kv_for_mislabeled_bob_recipient(home: &TempDir) -> String {
    let keystore_root = home.path().join("keys");
    let signer_kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let signer_pub = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &signer_kid).unwrap();
    let key_ctx = setup_member_key_context(home, ALICE_MEMBER_HANDLE, Some(&signer_kid));
    let bob_kid = list_kids(&keystore_root, BOB_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let mut mislabeled_bob = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, &bob_kid).unwrap();
    mislabeled_bob.protected.subject_handle = ALICE_MEMBER_HANDLE.to_string();
    let verified_members = build_verified_recipient_keys(&[mislabeled_bob]);
    let mut values = HashMap::new();
    values.insert("API_TOKEN".to_string(), "secret".to_string());
    let signing = SigningContext {
        signing_key: key_ctx.signing_key(),
        signer_kid: &signer_kid,
        signer_pub,
    };
    encrypt_kv_map_with_wrap_mutation(
        &values,
        &verified_members,
        &signing,
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap()
}

#[test]
fn test_doctor_ci_invalid_env_key_reports_fail_and_strict_warning() {
    let _guard = EnvGuard::new(&[
        "KAPSARO_PRIVATE_KEY",
        "KAPSARO_KEY_PASSWORD",
        "KAPSARO_STRICT_KEY_CHECKING",
    ]);
    std::env::set_var("KAPSARO_PRIVATE_KEY", "not-base64url");
    std::env::set_var("KAPSARO_KEY_PASSWORD", "password");
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "no");
    let checks = check_ci_readiness();

    assert!(
        has_check(&checks, "ci.env_key.present", DoctorStatus::Ok),
        "{checks:?}"
    );
    assert!(has_check(
        &checks,
        "ci.strict_key_checking",
        DoctorStatus::Warn
    ));
    assert!(has_check(&checks, "ci.env_key.load", DoctorStatus::Fail));
}

#[test]
fn test_doctor_ci_env_key_absent_reports_skip() {
    let _guard = EnvGuard::new(&["KAPSARO_PRIVATE_KEY", "KAPSARO_KEY_PASSWORD"]);
    std::env::remove_var("KAPSARO_PRIVATE_KEY");
    std::env::remove_var("KAPSARO_KEY_PASSWORD");
    let checks = check_ci_readiness();

    assert!(has_check(&checks, "ci.env_key.present", DoctorStatus::Skip));
}

#[test]
fn test_doctor_reports_missing_keystore_root_as_warning() {
    let home = TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let workspace = home.path().join("workspace");
    create_workspace_dirs(&workspace);

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(&checks, "keystore.root", DoctorStatus::Warn));
}

#[test]
fn test_doctor_reports_owner_config_parse_error_and_continues() {
    let _guard = EnvGuard::new(&["KAPSARO_MEMBER_HANDLE", "KAPSARO_PRIVATE_KEY"]);
    std::env::remove_var("KAPSARO_MEMBER_HANDLE");
    std::env::remove_var("KAPSARO_PRIVATE_KEY");
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    write_local_state_file(&home.path().join("config.toml"), "member_handle = [");
    let request = DoctorRequest {
        workspace: Some(workspace),
        home: Some(home.path().to_path_buf()),
        member_handle: None,
        verbose: false,
    };

    let report = execute_doctor_command(request).unwrap();
    let owner_check = find_check(report.checks(), "keystore.member", DoctorStatus::Fail);

    assert_eq!(report.exit_code(), 1);
    assert!(owner_check
        .reason_line()
        .is_some_and(|reason| reason.contains("Invalid TOML in config file")));
    assert!(has_check(
        report.checks(),
        "members.active.present",
        DoctorStatus::Ok
    ));
}

#[test]
fn test_doctor_reports_missing_active_private_key_as_failure() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = home.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    set_active_kid(ALICE_MEMBER_HANDLE, &kid, &keystore_root).unwrap();
    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from(kid).unwrap();
    let private_path = get_private_key_file_path_from_root(&keystore_root, &member_handle, &kid);
    fs::remove_file(private_path).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "keystore.private_key",
        DoctorStatus::Fail
    ));
}

#[cfg(unix)]
#[test]
fn test_doctor_preserves_unsafe_rule_for_symlinked_active_private_key() {
    use std::os::unix::fs::symlink;

    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = home.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .remove(0);
    set_active_kid(ALICE_MEMBER_HANDLE, &kid, &keystore_root).unwrap();
    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from(kid).unwrap();
    let private_path = get_private_key_file_path_from_root(&keystore_root, &member_handle, &kid);
    let outside = home.path().join("outside-private.json");
    fs::copy(&private_path, &outside).unwrap();
    fs::remove_file(&private_path).unwrap();
    symlink(&outside, &private_path).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);
    let check = find_check(&checks, "keystore.private_key", DoctorStatus::Fail);

    assert_eq!(check.rule.as_deref(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
}

#[cfg(unix)]
#[test]
fn test_doctor_preserves_unsafe_rule_for_symlinked_active_public_key() {
    use std::os::unix::fs::symlink;

    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = home.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .remove(0);
    set_active_kid(ALICE_MEMBER_HANDLE, &kid, &keystore_root).unwrap();
    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from(kid).unwrap();
    let public_path = get_public_key_file_path_from_root(&keystore_root, &member_handle, &kid);
    let outside = home.path().join("outside-public.json");
    fs::copy(&public_path, &outside).unwrap();
    fs::remove_file(&public_path).unwrap();
    symlink(&outside, &public_path).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);
    let check = find_check(&checks, "keystore.expiry", DoctorStatus::Fail);

    assert_eq!(check.rule.as_deref(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
}

#[test]
fn test_doctor_reports_invalid_trust_store_signature_as_failure() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    create_local_state_dir(trust_path.parent().unwrap());
    write_local_state_file(&trust_path, "{invalid-json");

    let checks = run_workspace_doctor(&home, &workspace);

    assert_trust_store_corruption_check(&checks);
}

/// A trust store that cannot be verified because the keystore root is gone is
/// an integrity failure: the pinned trust is read without its signature ever
/// being checked. The absence of the keystore root itself stays a warning.
#[test]
fn test_doctor_fails_when_trust_store_keystore_is_missing() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    save_empty_trust_store(&home);
    fs::rename(home.path().join("keys"), home.path().join("keys.saved")).unwrap();

    let report = execute_doctor_command(doctor_request(&home, &workspace)).unwrap();
    let check = find_check(report.checks(), "trust_store.integrity", DoctorStatus::Fail);

    assert_eq!(report.exit_code(), 1);
    assert!(has_check(
        report.checks(),
        "keystore.root",
        DoctorStatus::Warn
    ));
    assert_eq!(check.rule.as_deref(), Some("E_LOCAL_KEYSTORE_MISSING"));
}

#[test]
fn test_doctor_reports_missing_trust_signer_public_key_as_integrity_failure() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    save_empty_trust_store(&home);
    let keystore_root = home.path().join("keys");
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from(
        list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
            .unwrap()
            .remove(0),
    )
    .unwrap();
    fs::remove_file(
        keystore_root
            .join(member.as_str())
            .join(kid.as_str())
            .join("public.json"),
    )
    .unwrap();

    let report = execute_doctor_command(doctor_request(&home, &workspace)).unwrap();
    let check = find_check(report.checks(), "trust_store.integrity", DoctorStatus::Fail);

    assert_eq!(report.exit_code(), 1);
    assert_eq!(check.rule.as_deref(), Some("E_TRUST_SIGNER_KEY_MISSING"));
    assert!(check
        .reason_line()
        .is_some_and(|reason| reason.contains(kid.as_str())));
}

#[cfg(unix)]
#[test]
fn test_doctor_reports_symlinked_keystore_root_with_unsafe_rule() {
    use std::os::unix::fs::symlink;

    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = home.path().join("keys");
    let moved = home.path().join("keys.real");
    fs::rename(&keystore_root, &moved).unwrap();
    symlink(&moved, &keystore_root).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);
    let check = find_check(&checks, "keystore.root", DoctorStatus::Fail);

    assert_eq!(check.rule.as_deref(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
}

/// A local state root selected through a symlink is a supported setup, so
/// diagnostics read the trust store behind the link instead of stopping.
#[cfg(unix)]
#[test]
fn test_doctor_verifies_the_trust_store_through_a_symlinked_home() {
    use std::os::unix::fs::symlink;

    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    save_empty_trust_store(&home);
    let links = TempDir::new().unwrap();
    let selected_home = links.path().join("selected-home");
    symlink(home.path(), &selected_home).unwrap();
    let request = DoctorRequest {
        workspace: Some(workspace),
        home: Some(selected_home.clone()),
        member_handle: Some(ALICE_MEMBER_HANDLE.to_string()),
        verbose: false,
    };

    let report = execute_doctor_command(request).unwrap();
    let trust_check = find_check(report.checks(), "trust_store.present", DoctorStatus::Ok);

    assert_eq!(
        trust_check.message,
        "Local trust store is present and verified"
    );
    // The report names the root the operator selected, not the link target.
    assert_eq!(
        trust_check.subject,
        DoctorSubject::Path(format!(
            "{}/trust/{ALICE_MEMBER_HANDLE}.json",
            selected_home.display()
        ))
    );
}

#[cfg(unix)]
#[test]
fn test_doctor_reports_trust_store_unavailable_for_symlinked_trust_directory() {
    use std::os::unix::fs::symlink;

    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let outside = home.path().join("outside-trust");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, home.path().join("trust")).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);
    let trust_check = find_check(&checks, "trust_store.integrity", DoctorStatus::Fail);

    assert_eq!(
        trust_check.message,
        "Local trust store state is unavailable"
    );
    assert!(
        trust_check
            .reason_line()
            .is_some_and(|reason| reason.contains("refusing to open symlink as directory")),
        "{trust_check:#?}"
    );
    assert_eq!(
        trust_check.next_action.as_deref(),
        Some("inspect the local state path and permissions")
    );
    assert_eq!(
        trust_check.rule.as_deref(),
        Some("E_LOCAL_STATE_PATH_UNSAFE")
    );
}

/// The local state root is what this failure is about, so the finding names it
/// rather than the keystore directory the diagnosis never reached.
#[test]
fn test_doctor_reports_keystore_root_io_failure_with_unsafe_rule() {
    use crate::support::path::format_path_relative_to_cwd;

    let home = TempDir::new().unwrap();
    let workspace = home.path().join("workspace");
    create_workspace_dirs(&workspace);
    let base_dir = home.path().join("x".repeat(300));
    let request = DoctorRequest {
        workspace: Some(workspace),
        home: Some(base_dir.clone()),
        member_handle: Some(ALICE_MEMBER_HANDLE.to_string()),
        verbose: false,
    };

    let checks = execute_doctor_command(request).unwrap().checks().to_vec();
    let check = find_check(&checks, "keystore.root", DoctorStatus::Fail);

    assert_eq!(check.rule.as_deref(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert_eq!(
        check.subject,
        DoctorSubject::Path(format_path_relative_to_cwd(&base_dir))
    );
}

/// A keystore root other users can reach is named as a warning and the rest of
/// the diagnosis still runs, so the command still reports what else it found.
#[cfg(unix)]
#[test]
fn test_doctor_reports_insecure_keystore_root_permissions_as_a_warning() {
    use std::os::unix::fs::PermissionsExt;

    use crate::support::path::format_path_relative_to_cwd;

    for mode in [0o755, 0o777] {
        let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
        let keystore_root = home.path().join("keys");
        fs::set_permissions(&keystore_root, fs::Permissions::from_mode(mode)).unwrap();

        let report = execute_doctor_command(doctor_request(&home, &workspace)).unwrap();
        let subject = DoctorSubject::Path(format_path_relative_to_cwd(&keystore_root));
        let check = report
            .checks()
            .iter()
            .find(|check| check.id == "local_state.permissions" && check.subject == subject)
            .unwrap_or_else(|| panic!("mode {mode:o}: {:#?}", report.checks()));

        assert_eq!(check.status, DoctorStatus::Warn, "mode {mode:o}");
        assert!(
            has_check(report.checks(), "keystore.root", DoctorStatus::Ok),
            "mode {mode:o}: {:#?}",
            report.checks()
        );
        assert_eq!(
            check.message, "Local state entry is reachable by other users",
            "mode {mode:o}"
        );
        assert_eq!(
            check.rule.as_deref(),
            Some("W_LOCAL_STATE_PERMISSIONS"),
            "mode {mode:o}"
        );
        assert_eq!(
            check.next_action.as_deref(),
            Some("restrict local state permissions to owner only"),
            "mode {mode:o}"
        );
        assert!(
            check
                .reason_line()
                .is_some_and(|reason| reason.contains(&format!("{mode:04o}"))),
            "mode {mode:o}"
        );
    }
}

/// A member key directory doctor cannot open used to abort the whole command
/// with a generic error. It now becomes a FAIL for keystore.member, and every
/// check that would otherwise follow it still runs.
#[cfg(unix)]
#[test]
fn test_doctor_reports_an_unreadable_member_directory_and_keeps_going() {
    use std::os::unix::fs::PermissionsExt;

    if !permission_denial_can_be_staged(
        "test_doctor_reports_an_unreadable_member_directory_and_keeps_going",
    ) {
        return;
    }

    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let member_dir = home.path().join("keys").join(ALICE_MEMBER_HANDLE);
    fs::set_permissions(&member_dir, fs::Permissions::from_mode(0o000)).unwrap();

    let report = execute_doctor_command(doctor_request(&home, &workspace));

    fs::set_permissions(&member_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let checks = report.unwrap().checks().to_vec();

    let member_check = find_check(&checks, "keystore.member", DoctorStatus::Fail);
    assert_eq!(
        member_check.subject,
        DoctorSubject::Member(ALICE_MEMBER_HANDLE.to_string())
    );
    assert_eq!(
        member_check.message,
        "Keystore member namespace cannot be inspected safely"
    );
    assert!(member_check.reason_line().is_some(), "{member_check:#?}");
    assert_eq!(
        member_check.next_action.as_deref(),
        Some("inspect the local keystore entries")
    );

    // Checks that come after the member keystore stage still ran.
    assert!(has_check_id(&checks, "trust_store.present"), "{checks:#?}");
    assert!(has_check_id(&checks, "artifacts.discovered"), "{checks:#?}");
    assert!(has_check_id(&checks, "ci.env_key.present"), "{checks:#?}");
}

#[test]
fn test_doctor_warns_about_ignored_root_entry_during_owner_fallback() {
    let _guard = EnvGuard::new(&[
        "KAPSARO_MEMBER_HANDLE",
        "KAPSARO_PRIVATE_KEY",
        "KAPSARO_KEY_PASSWORD",
        "KAPSARO_STRICT_KEY_CHECKING",
    ]);
    std::env::remove_var("KAPSARO_MEMBER_HANDLE");
    std::env::remove_var("KAPSARO_PRIVATE_KEY");
    std::env::remove_var("KAPSARO_KEY_PASSWORD");
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    fs::write(home.path().join("keys/unexpected"), "unexpected").unwrap();
    let request = DoctorRequest {
        workspace: Some(workspace),
        home: Some(home.path().to_path_buf()),
        member_handle: None,
        verbose: false,
    };

    let report = execute_doctor_command(request).unwrap();
    let warning = find_check(report.checks(), "keystore.member", DoctorStatus::Warn);
    let member = find_check(report.checks(), "keystore.member", DoctorStatus::Ok);

    assert_eq!(report.exit_code(), 0);
    assert_eq!(
        warning.message,
        "Unexpected entries in the keystore directory"
    );
    assert_eq!(
        warning.next_action.as_deref(),
        Some("remove or move the entry out of the keystore directory")
    );
    assert!(warning.rule.is_none());
    assert!(warning
        .reason_line()
        .is_some_and(|reason| reason.contains("unexpected")));
    assert_eq!(
        member.subject,
        DoctorSubject::Member(ALICE_MEMBER_HANDLE.to_string())
    );
}

#[test]
fn test_doctor_warns_about_ignored_root_entry_for_explicit_owner() {
    let _guard = EnvGuard::new(&[
        "KAPSARO_MEMBER_HANDLE",
        "KAPSARO_PRIVATE_KEY",
        "KAPSARO_KEY_PASSWORD",
        "KAPSARO_STRICT_KEY_CHECKING",
    ]);
    std::env::remove_var("KAPSARO_MEMBER_HANDLE");
    std::env::remove_var("KAPSARO_PRIVATE_KEY");
    std::env::remove_var("KAPSARO_KEY_PASSWORD");
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    fs::write(home.path().join("keys/unexpected"), "unexpected").unwrap();

    let report = execute_doctor_command(doctor_request(&home, &workspace)).unwrap();
    let warning = find_check(report.checks(), "keystore.member", DoctorStatus::Warn);

    assert_eq!(report.exit_code(), 0);
    assert_eq!(
        warning.message,
        "Unexpected entries in the keystore directory"
    );
    assert_eq!(
        warning.next_action.as_deref(),
        Some("remove or move the entry out of the keystore directory")
    );
    assert!(warning.rule.is_none());
    assert!(warning
        .reason_line()
        .is_some_and(|reason| reason.contains("unexpected")));
}

#[test]
fn test_doctor_accepts_unrelated_member_directory() {
    // The full report exit code is asserted here, so the CI readiness checks
    // must observe a clean environment rather than a concurrent test's values.
    let _guard = EnvGuard::new(&[
        "KAPSARO_MEMBER_HANDLE",
        "KAPSARO_PRIVATE_KEY",
        "KAPSARO_KEY_PASSWORD",
        "KAPSARO_STRICT_KEY_CHECKING",
    ]);
    std::env::remove_var("KAPSARO_MEMBER_HANDLE");
    std::env::remove_var("KAPSARO_PRIVATE_KEY");
    std::env::remove_var("KAPSARO_KEY_PASSWORD");
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let stale_entry = home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(".tmp-stale");
    fs::create_dir(&stale_entry).unwrap();

    let report = execute_doctor_command(doctor_request(&home, &workspace)).unwrap();
    let check = find_check(report.checks(), "keystore.member", DoctorStatus::Ok);

    assert_eq!(report.exit_code(), 0);
    assert_eq!(
        check.subject,
        DoctorSubject::Member(ALICE_MEMBER_HANDLE.to_string())
    );
    assert!(check.reason.is_none());
    assert!(check.rule.is_none());
}

#[cfg(unix)]
#[test]
fn test_doctor_reports_symlinked_trust_store_as_integrity_failure() {
    use std::os::unix::fs::symlink;

    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    let outside = home.path().join("outside-trust.json");
    fs::write(&outside, "{}").unwrap();
    symlink(&outside, &trust_path).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);
    let check = find_check(&checks, "trust_store.integrity", DoctorStatus::Fail);

    assert_eq!(check.rule.as_deref(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
}

#[test]
fn test_doctor_ignores_unrelated_trust_file_when_store_is_missing() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let trust_dir = home.path().join("trust");
    fs::create_dir_all(&trust_dir).unwrap();
    fs::write(
        trust_dir.join(format!(".{ALICE_MEMBER_HANDLE}.json.tmp.stale")),
        "staging",
    )
    .unwrap();

    let checks = run_workspace_doctor(&home, &workspace);
    let check = find_check(&checks, "trust_store.present", DoctorStatus::Warn);

    assert_eq!(check.message, "Local trust store is missing");
    assert!(check.rule.is_none());
}

#[test]
fn test_doctor_warns_when_active_member_is_not_approved() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    save_empty_trust_store(&home);

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "trust_store.active_approval",
        DoctorStatus::Warn
    ));
}

#[test]
fn test_doctor_reports_incoming_member_and_duplicate_kid() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let active_file = workspace
        .join("members/active")
        .join(format!("{}.json", ALICE_MEMBER_HANDLE));
    let incoming_file = workspace.join("members/incoming/duplicate.json");
    fs::copy(active_file, incoming_file).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "members.incoming.pending",
        DoctorStatus::Warn
    ));
    assert!(has_check(&checks, "members.kid_unique", DoctorStatus::Fail));
}

#[test]
fn test_doctor_reports_invalid_artifact_read_failure() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    fs::write(
        workspace.join("secrets/bad.kvenc"),
        "not an encrypted artifact",
    )
    .unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(&checks, "artifacts.read", DoctorStatus::Fail));
}

#[test]
fn test_doctor_warns_when_artifact_recipients_differ_from_active_members() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let content = encrypted_kv_for_alice_only(&home);
    fs::write(workspace.join("secrets/default.kvenc"), content).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(&checks, "artifact.signature", DoctorStatus::Ok));
    assert!(has_check(
        &checks,
        "artifact.signer_active",
        DoctorStatus::Ok
    ));
    assert!(has_check(
        &checks,
        "artifact.recipients_active",
        DoctorStatus::Warn
    ));
}

/// A member document that will not load leaves the member set unknown. Judging
/// the artifacts against an empty set would mark every signer as no longer a
/// member and send the operator to rewrap, which repairs nothing when the fault
/// is in members/active itself.
#[test]
fn test_doctor_reports_unreadable_active_members_instead_of_failing_every_signer() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    fs::write(
        workspace.join("secrets/default.kvenc"),
        encrypted_kv_for_alice_only(&home),
    )
    .unwrap();
    fs::write(
        workspace.join(format!("members/active/{BOB_MEMBER_HANDLE}.json")),
        "{ not a member document",
    )
    .unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "artifacts.active_members",
        DoctorStatus::Fail
    ));
    assert!(has_check(&checks, "artifact.signature", DoctorStatus::Ok));
    assert!(
        !has_check_id(&checks, "artifact.signer_active"),
        "{checks:#?}"
    );
    assert!(
        !has_check_id(&checks, "artifact.recipients_active"),
        "{checks:#?}"
    );
}

#[test]
fn test_doctor_reports_tampered_artifact_signature_failure() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let content = encrypted_kv_for_alice_only(&home).replacen("API_TOKEN", "API_TOKFN", 1);
    fs::write(workspace.join("secrets/default.kvenc"), content).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(&checks, "artifact.signature", DoctorStatus::Fail));
    assert!(!has_check(
        &checks,
        "artifact.signer_active",
        DoctorStatus::Ok
    ));
}

#[test]
fn test_doctor_reports_artifact_signer_not_active() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    fs::write(
        workspace.join("secrets/default.kvenc"),
        encrypted_kv_for_alice_only(&home),
    )
    .unwrap();
    fs::remove_file(
        workspace
            .join("members/active")
            .join(format!("{}.json", ALICE_MEMBER_HANDLE)),
    )
    .unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "artifact.signer_active",
        DoctorStatus::Fail
    ));
}

#[test]
fn test_doctor_reports_artifact_recipient_handle_conflict() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    fs::write(
        workspace.join("secrets/default.kvenc"),
        encrypted_kv_for_mislabeled_bob_recipient(&home),
    )
    .unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "artifact.recipient_handle",
        DoctorStatus::Fail
    ));
}

#[test]
fn test_doctor_without_member_handle_reports_owner_warnings_when_ambiguous() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let request = DoctorRequest {
        workspace: Some(workspace),
        home: Some(home.path().to_path_buf()),
        member_handle: None,
        verbose: false,
    };

    let checks = execute_doctor_command(request).unwrap().checks().to_vec();

    assert!(has_check(&checks, "keystore.member", DoctorStatus::Warn));
    assert!(has_check(
        &checks,
        "trust_store.present",
        DoctorStatus::Warn
    ));
}

#[test]
fn test_doctor_uses_opened_keystore_identity_for_owner_and_trust_store() {
    let _guard = EnvGuard::new(&["KAPSARO_MEMBER_HANDLE", "KAPSARO_PRIVATE_KEY"]);
    std::env::remove_var("KAPSARO_MEMBER_HANDLE");
    std::env::remove_var("KAPSARO_PRIVATE_KEY");
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    save_empty_trust_store(&home);
    let keystore_root = home.path().join("keys");
    let active_kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .remove(0);
    set_active_kid(ALICE_MEMBER_HANDLE, &active_kid, &keystore_root).unwrap();
    let (replacement_home, _) = setup_test_workspace_from_fixtures(&[BOB_MEMBER_HANDLE]);
    let opened_keystore = home.path().join("keys.opened");
    let replacement_keystore = replacement_home.path().join("keys");
    set_post_keystore_open_hook(move || {
        fs::rename(&keystore_root, &opened_keystore).unwrap();
        fs::rename(&replacement_keystore, &keystore_root).unwrap();
    });
    let request = DoctorRequest {
        workspace: Some(workspace),
        home: Some(home.path().to_path_buf()),
        member_handle: None,
        verbose: false,
    };

    let checks = execute_doctor_command(request).unwrap().checks().to_vec();
    let member = find_check(&checks, "keystore.member", DoctorStatus::Ok);

    assert_eq!(
        member.subject,
        DoctorSubject::Member(ALICE_MEMBER_HANDLE.to_string())
    );
    assert!(has_check(&checks, "keystore.private_key", DoctorStatus::Ok));
    assert!(has_check(&checks, "trust_store.present", DoctorStatus::Ok));
}

#[test]
fn test_doctor_stays_bound_to_the_opened_keystore_for_ambiguous_owner() {
    let _guard = EnvGuard::new(&["KAPSARO_MEMBER_HANDLE", "KAPSARO_PRIVATE_KEY"]);
    std::env::remove_var("KAPSARO_MEMBER_HANDLE");
    std::env::remove_var("KAPSARO_PRIVATE_KEY");
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (replacement_home, _) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = home.path().join("keys");
    let opened_keystore = home.path().join("keys.opened");
    let replacement_keystore = replacement_home.path().join("keys");
    set_post_keystore_open_hook(move || {
        fs::rename(&keystore_root, &opened_keystore).unwrap();
        fs::rename(&replacement_keystore, &keystore_root).unwrap();
    });
    let request = DoctorRequest {
        workspace: Some(workspace),
        home: Some(home.path().to_path_buf()),
        member_handle: None,
        verbose: false,
    };

    let checks = execute_doctor_command(request).unwrap().checks().to_vec();

    assert!(has_check(&checks, "keystore.member", DoctorStatus::Warn));
    assert!(has_check(
        &checks,
        "trust_store.present",
        DoctorStatus::Warn
    ));
}

#[test]
fn test_doctor_env_key_without_explicit_member_preserves_missing_home() {
    let _guard = EnvGuard::new(&[
        "KAPSARO_MEMBER_HANDLE",
        "KAPSARO_PRIVATE_KEY",
        "KAPSARO_KEY_PASSWORD",
    ]);
    std::env::remove_var("KAPSARO_MEMBER_HANDLE");
    std::env::set_var("KAPSARO_PRIVATE_KEY", "not-base64url");
    std::env::set_var("KAPSARO_KEY_PASSWORD", "password");
    let temp = local_state_temp_dir();
    let workspace = temp.path().join("workspace");
    let missing_home = temp.path().join("missing-home");
    create_workspace_dirs(&workspace);
    let request = DoctorRequest {
        workspace: Some(workspace),
        home: Some(missing_home.clone()),
        member_handle: None,
        verbose: false,
    };

    let checks = execute_doctor_command(request).unwrap().checks().to_vec();

    assert!(!missing_home.exists());
    assert!(has_check(&checks, "keystore.root", DoctorStatus::Warn));
    assert!(has_check(&checks, "keystore.member", DoctorStatus::Warn));
}

#[test]
#[cfg(unix)]
fn test_doctor_reports_symlinked_keystore_root_entry_as_ignored() {
    use std::os::unix::fs::symlink;

    let _guard = EnvGuard::new(&["KAPSARO_MEMBER_HANDLE", "KAPSARO_PRIVATE_KEY"]);
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let outside = home.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, home.path().join("keys/linked")).unwrap();

    let report = execute_doctor_command(doctor_request(&home, &workspace)).unwrap();

    let check = find_check(report.checks(), "keystore.member", DoctorStatus::Warn);
    assert_eq!(
        check.message,
        "Unexpected entries in the keystore directory"
    );
    assert!(
        check
            .reason_line()
            .is_some_and(|reason| reason.contains("linked")),
        "a symlink is never read as a member, so diagnostics must name it: {check:#?}"
    );
}

/// An entry name is chosen by whoever can write the keystore directory, so one
/// of them may hold the separator the reported line is read with. The names stay
/// apart in the check, and a consumer reads each one whole.
#[test]
fn test_doctor_keeps_ignored_keystore_entry_names_apart() {
    let _guard = EnvGuard::new(&["KAPSARO_MEMBER_HANDLE", "KAPSARO_PRIVATE_KEY"]);
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = home.path().join("keys");
    fs::write(keystore_root.join("first, second"), b"").unwrap();
    fs::write(keystore_root.join("third"), b"").unwrap();

    let report = execute_doctor_command(doctor_request(&home, &workspace)).unwrap();

    let check = find_check(report.checks(), "keystore.member", DoctorStatus::Warn);
    let Some(DoctorReason::Names(names)) = check.reason.as_ref() else {
        panic!("ignored entry names must stay apart: {check:#?}");
    };
    let mut names = names.clone();
    names.sort();
    assert_eq!(
        names,
        vec!["first, second".to_string(), "third".to_string()]
    );
}

/// Normal readers ignore staging names, so Doctor reports residue and recovery.
#[test]
fn test_doctor_reports_an_entry_an_unfinished_write_staged() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let staged = home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(".tmp-3f2504e0-4f89-41d3-9a0c-0305e82c3301");
    fs::create_dir(&staged).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    let check = find_check(&checks, "local_state.write_residue", DoctorStatus::Warn);
    assert_eq!(
        check.next_action.as_deref(),
        Some(
            "inspect the staged entry and remove it once no kapsaro command is running and its \
             contents are no longer needed"
        )
    );
}

/// The member namespace is opened under the handle with `O_NOFOLLOW`, so a
/// symlink standing there is an entry kapsaro refuses to read. Reporting it as
/// a member that is simply absent would leave the operator with a warning where
/// somebody else is holding the name their keys are read under.
#[test]
#[cfg(unix)]
fn test_doctor_reports_a_symlink_standing_in_for_the_owner_key_directory() {
    use std::os::unix::fs::symlink;

    let _guard = EnvGuard::new(&["KAPSARO_MEMBER_HANDLE", "KAPSARO_PRIVATE_KEY"]);
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let member_dir = home.path().join("keys").join(ALICE_MEMBER_HANDLE);
    let moved = home.path().join("moved-keys");
    fs::rename(&member_dir, &moved).unwrap();
    symlink(&moved, &member_dir).unwrap();

    let report = execute_doctor_command(doctor_request(&home, &workspace)).unwrap();

    let check = find_check(report.checks(), "keystore.member", DoctorStatus::Fail);
    assert_eq!(
        check.message,
        "Keystore member namespace cannot be inspected safely"
    );
    assert_eq!(
        check.subject,
        DoctorSubject::Member(ALICE_MEMBER_HANDLE.to_string())
    );
    assert_eq!(check.rule.as_deref(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
}

/// One member document that will not parse must not take the report with it.
/// The diagnosis is what an operator repairs a broken workspace from, so the
/// keystore, the permissions and the members it already judged all still reach
/// them, and only the approval of that one member goes unanswered.
#[test]
fn test_doctor_keeps_its_report_when_an_active_member_document_is_invalid() {
    let _guard = EnvGuard::new(&["KAPSARO_MEMBER_HANDLE", "KAPSARO_PRIVATE_KEY"]);
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    save_empty_trust_store(&home);
    fs::write(
        workspace
            .join("members/active")
            .join(format!("{}.json", BOB_MEMBER_HANDLE)),
        "not a document",
    )
    .unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(&checks, "keystore.member", DoctorStatus::Ok));
    assert!(has_check(
        &checks,
        "members.active.file",
        DoctorStatus::Fail
    ));
    assert!(has_check(&checks, "trust_store.present", DoctorStatus::Ok));
    let skipped = find_check(&checks, "trust_store.active_approval", DoctorStatus::Skip);
    assert_eq!(
        skipped.subject,
        DoctorSubject::Member(BOB_MEMBER_HANDLE.to_string())
    );
    assert_eq!(skipped.message, "Active member approval was not checked");
}
