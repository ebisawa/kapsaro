// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::api::key::LocalKeyStore;
use crate::api::kv::{KvEncArtifact, KvInputEntry, KvReadOperation};
use crate::api::secret::SecretString;
use crate::api::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, LocalTrustStore, ReadTrustExceptions,
    TrustApproval, TrustDecision, TrustPolicyEvaluator,
};
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::fail_next_trust_store_save;
use crate::service::kv::mutation::{
    authorized_mutation_count, import_kv_command_with_recipient_set_confirmation,
    reevaluate_mutation_write_plan_after_review, reset_authorized_mutation_count,
    resolve_mutation_write_plan, set_kv_command_with_recipient_set_confirmation,
    set_post_authorized_mutation_hook, set_post_recipient_approval_hook,
    unset_kv_command_with_recipient_set_confirmation, MutationWriteTrustPlan,
};
use crate::service::trust::management::{remove_known_key_command, remove_recipient_set_command};
use crate::service::trust::review::{
    review_write_recipient_trust, TrustReviewContext, WriteRecipientTrustReviewPlan,
};
use crate::service_test_utils::{
    build_test_signing_command_options, build_test_trust_command_session_from_options,
    resolve_test_write_session, TestCommandOptions, TestWriteSession,
};
use crate::support::warning::LocalStateWarningGuard;
use crate::test_support::storage::keystore::active::set_active_kid;
use crate::test_support::storage::keystore::storage::{list_kids, load_public_key};
use crate::test_utils::{
    build_expiring_soon_timestamp, member_handle, save_active_public_key_to_workspace,
    save_public_key, setup_member_key_context, setup_test_workspace_from_fixtures,
    setup_trust_store_for_workspace, update_active_private_key_expires_at, with_temp_cwd, EnvGuard,
};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";

fn kv_input(key: impl Into<String>, value: impl Into<String>) -> KvInputEntry {
    KvInputEntry::new(key, SecretString::new(value.into()))
}

fn resolve_test_kv_target_path(
    options: &TestCommandOptions,
    file_name: Option<&str>,
) -> crate::Result<std::path::PathBuf> {
    let name = file_name.unwrap_or("default");
    Ok(options
        .workspace
        .as_ref()
        .expect("test workspace")
        .join("secrets")
        .join(format!("{name}.kvenc")))
}

#[derive(Clone, Copy)]
enum KvReadMode<'a> {
    All,
    Single(&'a str),
}

fn evaluate_write_plan<'a>(
    session: &'a TestWriteSession,
    name: Option<&str>,
    allow_missing: bool,
) -> MutationWriteTrustPlan<'a> {
    resolve_mutation_write_plan(
        &session.directories,
        &session.trust,
        session.options,
        name,
        allow_missing,
    )
    .unwrap()
}

fn activate_fixture_key(home: &std::path::Path) {
    let keystore_root = home.join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    set_active_kid(ALICE_MEMBER_HANDLE, &kid, &keystore_root).unwrap();
}

fn read_kv_values(
    options: &TestCommandOptions,
    mode: KvReadMode<'_>,
) -> std::collections::BTreeMap<String, String> {
    let session = resolve_test_write_session(options, ALICE_MEMBER_HANDLE);
    let artifact =
        KvEncArtifact::load(resolve_test_kv_target_path(options, None).unwrap()).unwrap();
    let verified = artifact.verify(options.operation_options()).unwrap();
    let members = CurrentMemberSnapshot::load(options.workspace.as_ref().unwrap()).unwrap();
    let key_store =
        LocalKeyStore::open(options.resolve_keystore_root().unwrap()).expect("open keystore");
    let trust_store = LocalTrustStore::open(
        options.resolve_base_dir().unwrap(),
        member_handle(ALICE_MEMBER_HANDLE),
    )
    .expect("open trust store");
    let store = trust_store
        .load_verified(&key_store)
        .unwrap()
        .map(|loaded| loaded.into_store());
    let evaluator = TrustPolicyEvaluator::new(members, store);
    let operation = match mode {
        KvReadMode::All => KvReadOperation::Entries,
        KvReadMode::Single(key) => KvReadOperation::Entry(key.to_string()),
    };
    let TrustDecision::Trusted(trusted) = evaluator
        .evaluate_kv(
            &verified,
            session.trust.key_ctx(),
            operation,
            options.operation_options(),
            ReadTrustExceptions::none(),
        )
        .unwrap()
    else {
        panic!("expected trusted KV read");
    };
    let values = match mode {
        KvReadMode::All => trusted.decrypt_entries().unwrap(),
        KvReadMode::Single(key) => {
            std::collections::BTreeMap::from([(key.to_string(), trusted.decrypt_entry().unwrap())])
        }
    };
    values
        .into_iter()
        .map(|(key, value)| (key, value.into_plain_string_for_output()))
        .collect()
}

fn set_kv_with_approved_member_set(
    plan: &MutationWriteTrustPlan<'_>,
    entries: Vec<KvInputEntry>,
) -> crate::Result<()> {
    set_kv_command_with_recipient_set_confirmation(plan, entries, |_, _| Ok(true))
}

fn unset_kv_with_approved_member_set(
    plan: &MutationWriteTrustPlan<'_>,
    key: &str,
) -> crate::Result<()> {
    unset_kv_command_with_recipient_set_confirmation(plan, key, |_, _| Ok(true))
}

fn approve_recipient_keys_and_reevaluate<'a>(
    plan: MutationWriteTrustPlan<'a>,
) -> MutationWriteTrustPlan<'a> {
    review_write_recipient_trust(
        TrustReviewContext {
            trust: plan.trust_session(),
            warnings: &plan.warnings,
        },
        WriteRecipientTrustReviewPlan {
            signer_trust: None,
            recipient_trust: &plan.recipient_trust,
            recipient_context_label: "KV recipients",
        },
        |_| {},
        |_, _| Ok(true),
        |_, _, _| Ok(true),
        |candidates, _| Ok(candidates.to_vec()),
    )
    .unwrap();
    reevaluate_mutation_write_plan_after_review(plan).unwrap()
}

fn remove_bob_known_key(options: &TestCommandOptions, home: &std::path::Path) {
    let bob_kid = list_kids(&home.join("keys"), BOB_MEMBER_HANDLE)
        .unwrap()
        .remove(0);
    let trust = build_test_trust_command_session_from_options(options, ALICE_MEMBER_HANDLE);
    remove_known_key_command(&trust, &bob_kid).unwrap();
}

fn remove_approved_recipient_set(options: &TestCommandOptions) {
    let path = resolve_test_kv_target_path(options, None).unwrap();
    let artifact = KvEncArtifact::load(path).unwrap();
    let sid = artifact
        .verify(options.operation_options())
        .unwrap()
        .recipient_set_subject()
        .unwrap()
        .sid()
        .to_string();
    let trust = build_test_trust_command_session_from_options(options, ALICE_MEMBER_HANDLE);
    remove_recipient_set_command(&trust, &sid).unwrap();
}

#[test]
fn test_execute_set_creates_default_kv_file_with_entry() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let plan = evaluate_write_plan(&execution, None, true);

        set_kv_with_approved_member_set(
            &plan,
            vec![kv_input("DATABASE_URL", "postgres://localhost/db")],
        )
        .unwrap();

        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        let content = fs::read_to_string(&kv_path).unwrap();
        assert!(content.contains("DATABASE_URL"));
    });
}

#[test]
fn test_execute_set_uses_recipient_key_approval_saved_by_same_command() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let plan = evaluate_write_plan(&execution, None, true);
        let plan = approve_recipient_keys_and_reevaluate(plan);

        set_kv_with_approved_member_set(
            &plan,
            vec![kv_input("DATABASE_URL", "postgres://localhost/db")],
        )
        .unwrap();

        let values = read_kv_values(&options, KvReadMode::Single("DATABASE_URL"));
        assert_eq!(
            values.get("DATABASE_URL").map(String::as_str),
            Some("postgres://localhost/db")
        );
    });
}

#[test]
fn test_execute_unset_uses_recipient_key_approval_saved_by_same_command() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "value1")]).unwrap();
        remove_bob_known_key(&options, temp_dir.path());

        let plan = evaluate_write_plan(&execution, None, false);
        let plan = approve_recipient_keys_and_reevaluate(plan);
        unset_kv_with_approved_member_set(&plan, "KEY1").unwrap();

        assert!(read_kv_values(&options, KvReadMode::All).is_empty());
    });
}

#[test]
fn test_execute_import_uses_recipient_key_approval_saved_by_same_command() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_bob_known_key(&options, temp_dir.path());

        let plan = evaluate_write_plan(&execution, None, true);
        let plan = approve_recipient_keys_and_reevaluate(plan);
        let imported = import_kv_command_with_recipient_set_confirmation(
            &plan,
            "KEY1=new\nKEY2=added\n",
            |_, _| Ok(true),
        )
        .unwrap();

        let values = read_kv_values(&options, KvReadMode::All);
        assert_eq!(imported, 2);
        assert_eq!(values.get("KEY1").map(String::as_str), Some("new"));
        assert_eq!(values.get("KEY2").map(String::as_str), Some("added"));
    });
}

#[test]
fn test_execute_existing_set_approves_recipient_set_before_single_mutation() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let reviewed = evaluate_write_plan(&execution, None, true);
        reset_authorized_mutation_count();
        let mut confirmations = 0;

        set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| {
                confirmations += 1;
                Ok(true)
            },
        )
        .unwrap();

        assert_eq!(confirmations, 1);
        assert_eq!(authorized_mutation_count(), 1);
        let values = read_kv_values(&options, KvReadMode::Single("KEY1"));
        assert_eq!(values.get("KEY1").map(String::as_str), Some("new"));
    });
}

#[test]
fn test_execute_existing_set_rejects_mixed_known_key_and_recipient_set_review() {
    assert_existing_set_rejects_mixed_known_key_and_recipient_set_review(true);
}

#[test]
fn test_execute_existing_set_rejects_mixed_reviews_non_interactive_error() {
    assert_existing_set_rejects_mixed_known_key_and_recipient_set_review(false);
}

fn assert_existing_set_rejects_mixed_known_key_and_recipient_set_review(is_interactive: bool) {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_bob_known_key(&options, temp_dir.path());
        remove_approved_recipient_set(&options);

        let mut reviewed = evaluate_write_plan(&execution, None, true);
        reviewed.trust_context.review_available = is_interactive;
        let artifact_path = resolve_test_kv_target_path(&options, None).unwrap();
        let trust_path =
            get_trust_store_file_path(temp_dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
        let artifact_before = fs::read(&artifact_path).unwrap();
        let trust_before = fs::read(&trust_path).unwrap();
        let mut confirmations = 0;
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| {
                confirmations += 1;
                Ok(true)
            },
        )
        .expect_err("mixed trust review requests must be reviewed again");

        assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
        assert_eq!(
            error.format_user_message(),
            "KV mutation trust changed and must be reviewed again."
        );
        assert_eq!(confirmations, 0);
        assert_eq!(authorized_mutation_count(), 0);
        assert_eq!(fs::read(artifact_path).unwrap(), artifact_before);
        assert_eq!(fs::read(trust_path).unwrap(), trust_before);
    });
}

/// The recipient-set prompt runs before the secrets directory is locked.
///
/// A directory lock is given up on a timeout, so an operator stopping at the
/// prompt would fail every other command working the same tree. Taking a lock
/// this thread already holds is refused outright, so a take that succeeds from
/// inside the prompt is what says the prompt is outside the lock.
#[cfg(unix)]
#[test]
fn test_execute_existing_set_prompts_outside_the_secrets_directory_lock() {
    use crate::support::fs::lock::with_exclusive_locked_directory;
    use std::sync::Arc;

    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let secrets_dir = Arc::clone(reviewed.secrets_directory());
        let mut confirmations = 0;

        set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| {
                confirmations += 1;
                with_exclusive_locked_directory(secrets_dir.as_ref(), |_| Ok(()))
                    .expect("recipient-set prompt must not hold the secrets directory lock");
                Ok(true)
            },
        )
        .unwrap();

        assert_eq!(confirmations, 1);
        let values = read_kv_values(&options, KvReadMode::Single("KEY1"));
        assert_eq!(values.get("KEY1").map(String::as_str), Some("new"));
    });
}

#[test]
fn test_execute_existing_set_rejection_preserves_artifact_without_mutation() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let path = resolve_test_kv_target_path(&options, None).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| Ok(false),
        )
        .expect_err("recipient-set rejection must stop the existing mutation");

        assert!(error.to_string().contains("approval declined"));
        assert_eq!(authorized_mutation_count(), 0);
        assert_eq!(fs::read_to_string(path).unwrap(), before);
    });
}

#[test]
fn test_execute_existing_set_preserves_missing_recipient_error_non_interactive() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let mut reviewed = evaluate_write_plan(&execution, None, true);
        reviewed.trust_context.review_available = false;
        let path = resolve_test_kv_target_path(&options, None).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| panic!("non-interactive review must not prompt"),
        )
        .expect_err("missing recipient set must preserve its stable error");

        assert_eq!(error.rule(), Some("E_RECIPIENT_TRUST_MISSING"));
        assert_eq!(authorized_mutation_count(), 0);
        assert_eq!(fs::read_to_string(path).unwrap(), before);
    });
}

#[test]
fn test_execute_existing_set_preserves_changed_recipient_error_non_interactive() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        let path = resolve_test_kv_target_path(&options, None).unwrap();
        let artifact = KvEncArtifact::load(&path).unwrap();
        let sid = artifact
            .verify(options.operation_options())
            .unwrap()
            .recipient_set_subject()
            .unwrap()
            .sid();
        let alice_kid = LocalKeyStore::open(temp_dir.path().join("keys"))
            .expect("open keystore")
            .load_active_kid(&member_handle(ALICE_MEMBER_HANDLE))
            .unwrap()
            .unwrap()
            .into_string();
        LocalTrustStore::open(temp_dir.path(), member_handle(ALICE_MEMBER_HANDLE))
            .expect("open trust store")
            .apply_approvals_with_conflict_handling(
                vec![TrustApproval::recipient_set_for_test(sid, vec![alice_kid])],
                initial.trust_session().key_ctx(),
                ApprovalConflictHandling::merge(),
            )
            .unwrap();
        let mut reviewed = evaluate_write_plan(&execution, None, true);
        reviewed.trust_context.review_available = false;
        let before = fs::read_to_string(&path).unwrap();
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| panic!("non-interactive review must not prompt"),
        )
        .expect_err("changed recipient set must preserve its stable error");

        assert_eq!(error.rule(), Some("E_RECIPIENT_SET_CHANGED"));
        assert_eq!(authorized_mutation_count(), 0);
        assert_eq!(fs::read_to_string(path).unwrap(), before);
    });
}

#[test]
fn test_execute_existing_set_rechecks_artifact_immediately_after_confirmation() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let path = resolve_test_kv_target_path(&options, None).unwrap();
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| {
                fs::write(&path, "concurrent artifact").unwrap();
                Ok(true)
            },
        )
        .expect_err("artifact change during confirmation must require a new review");

        assert!(error.to_string().contains("changed since review"));
        assert_eq!(authorized_mutation_count(), 0);
        assert_eq!(fs::read_to_string(path).unwrap(), "concurrent artifact");
    });
}

#[test]
fn test_execute_existing_set_rechecks_members_immediately_after_confirmation() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let path = resolve_test_kv_target_path(&options, None).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        let bob_active = workspace_dir
            .join("members")
            .join("active")
            .join(format!("{}.json", BOB_MEMBER_HANDLE));
        let bob_incoming = workspace_dir
            .join("members")
            .join("incoming")
            .join(format!("{}.json", BOB_MEMBER_HANDLE));
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| {
                fs::rename(&bob_active, &bob_incoming).unwrap();
                Ok(true)
            },
        )
        .expect_err("member change during confirmation must require a new review");

        assert!(error.to_string().contains("active members changed"));
        assert_eq!(authorized_mutation_count(), 0);
        assert_eq!(fs::read_to_string(path).unwrap(), before);
    });
}

/// Copy the active member documents of one workspace into a stand-in tree.
fn copy_active_members(source: &std::path::Path, standin: &std::path::Path) {
    let active = standin.join("members").join("active");
    fs::create_dir_all(&active).unwrap();
    for entry in fs::read_dir(source.join("members").join("active")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), active.join(entry.file_name())).unwrap();
    }
}

/// Take one member out of a workspace's active set.
fn drop_active_member(workspace: &std::path::Path, member_handle: &str) {
    let members = workspace.join("members");
    fs::rename(
        members.join("active").join(format!("{member_handle}.json")),
        members
            .join("incoming")
            .join(format!("{member_handle}.json")),
    )
    .unwrap();
}

/// The final member check answers from the workspace the command fixed.
///
/// A workspace repointed while the operator was deciding leaves two trees: the
/// one the write lands in, held open since the command started, and whatever
/// now stands at the configured path. Reading the member set from that path
/// would let a stand-in holding the reviewed members authorize a write into a
/// tree that has since dropped one of them.
#[test]
fn test_execute_existing_set_rechecks_members_in_the_fixed_workspace() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let moved_aside = temp_dir.path().join("workspace.original");

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let path = resolve_test_kv_target_path(&options, None).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        let artifact_under_original = moved_aside
            .join("secrets")
            .join(path.file_name().expect("the artifact has a file name"));

        let original = workspace_dir.clone();
        let standin = temp_dir.path().join("workspace.standin");
        let swapped_aside = moved_aside.clone();
        set_post_recipient_approval_hook(move || {
            copy_active_members(&original, &standin);
            drop_active_member(&original, BOB_MEMBER_HANDLE);
            fs::rename(&original, &swapped_aside).unwrap();
            fs::rename(&standin, &original).unwrap();
        });
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| Ok(true),
        )
        .expect_err("a member dropped from the fixed workspace must require a new review");

        assert!(
            error.to_string().contains("active members changed"),
            "unexpected message: {error}"
        );
        assert_eq!(authorized_mutation_count(), 0);
        assert_eq!(fs::read_to_string(artifact_under_original).unwrap(), before);
    });
}

#[test]
fn test_execute_existing_set_rechecks_artifact_after_recipient_approval() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let path = resolve_test_kv_target_path(&options, None).unwrap();
        let concurrent_path = path.clone();
        set_post_recipient_approval_hook(move || {
            fs::write(concurrent_path, "post-approval artifact").unwrap();
        });
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| Ok(true),
        )
        .expect_err("post-approval artifact change must require a new review");

        assert!(error.to_string().contains("changed since review"));
        assert_eq!(authorized_mutation_count(), 0);
        assert_eq!(fs::read_to_string(path).unwrap(), "post-approval artifact");
    });
}

#[test]
fn test_execute_existing_set_rechecks_post_approval_trust_snapshot() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let trust_path =
            get_trust_store_file_path(temp_dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
        let pre_approval_trust = fs::read_to_string(&trust_path).unwrap();
        let reviewed = evaluate_write_plan(&execution, None, true);
        let path = resolve_test_kv_target_path(&options, None).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        set_post_recipient_approval_hook(move || {
            fs::write(trust_path, pre_approval_trust).unwrap();
        });
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| Ok(true),
        )
        .expect_err("post-approval trust rollback must require a new review");

        assert!(error
            .to_string()
            .contains("KV mutation trust changed and must be reviewed again."));
        assert_eq!(authorized_mutation_count(), 0);
        assert_eq!(fs::read_to_string(path).unwrap(), before);
    });
}

#[test]
fn test_execute_new_set_rechecks_post_approval_recipient_set() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let trust_path =
            get_trust_store_file_path(temp_dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
        let pre_approval_trust = fs::read_to_string(&trust_path).unwrap();
        let path = workspace_dir.join("secrets").join("default.kvenc");
        set_post_recipient_approval_hook(move || {
            fs::write(trust_path, pre_approval_trust).unwrap();
        });
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "value1")],
            |_, _| Ok(true),
        )
        .expect_err("post-approval recipient-set rollback must require a new review");

        assert!(error
            .to_string()
            .contains("KV mutation trust changed and must be reviewed again."));
        assert!(!path.exists());
        assert_eq!(authorized_mutation_count(), 0);
    });
}

#[test]
fn test_execute_new_set_keeps_post_approval_checks_bound_to_loaded_keystore() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let keystore_root = temp_dir.path().join("keys");
        let replacement_root = temp_dir.path().join("keys.replacement");
        let bound_root = temp_dir.path().join("keys.bound");
        let alice_kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
            .unwrap()
            .remove(0);
        let mut replacement =
            load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &alice_kid).unwrap();
        replacement.protected.keys.sig.x =
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_string();
        save_public_key(
            &replacement_root,
            ALICE_MEMBER_HANDLE,
            &alice_kid,
            &replacement,
        )
        .unwrap();
        set_post_recipient_approval_hook(move || {
            fs::rename(&keystore_root, &bound_root).unwrap();
            fs::rename(&replacement_root, &keystore_root).unwrap();
        });

        set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "value1")],
            |_, _| Ok(true),
        )
        .expect("fixed keystore must verify all post-approval snapshots");

        assert!(workspace_dir.join("secrets/default.kvenc").exists());
    });
}

#[cfg(unix)]
#[test]
fn test_execute_existing_set_reports_missing_signer_key_when_verification_keystore_disappears() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let keys_path = temp_dir.path().join("keys");
        set_post_recipient_approval_hook(move || {
            fs::remove_dir_all(keys_path).unwrap();
        });
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| Ok(true),
        )
        .expect_err("missing trust verification keys must stop the mutation");

        assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
        assert_eq!(error.recovery(), Some("E_TRUST_SIGNER_KEY_MISSING"));
        assert_eq!(authorized_mutation_count(), 0);
    });
}

#[cfg(unix)]
#[test]
fn test_execute_existing_set_keeps_final_authorization_bound_to_opened_home() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let external_workspace = temp_dir.path().with_extension("workspace");
    fs::rename(&workspace_dir, &external_workspace).unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &external_workspace);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &external_workspace,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        remove_approved_recipient_set(&options);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let home_path = temp_dir.path().to_path_buf();
        let opened_home = home_path.with_extension("opened");
        let replacement_home = home_path.with_extension("replacement");
        let replacement_trust =
            get_trust_store_file_path(&replacement_home, &member_handle(ALICE_MEMBER_HANDLE));
        fs::create_dir(&replacement_home).unwrap();
        fs::set_permissions(&replacement_home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(replacement_trust.parent().unwrap()).unwrap();
        fs::set_permissions(
            replacement_trust.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(&replacement_trust, "replacement-trust").unwrap();
        fs::set_permissions(&replacement_trust, fs::Permissions::from_mode(0o600)).unwrap();
        let replacement_bytes = fs::read(&replacement_trust).unwrap();
        let swap_home = home_path.clone();
        let swap_opened = opened_home.clone();
        let swap_replacement = replacement_home.clone();
        set_post_recipient_approval_hook(move || {
            fs::rename(&swap_home, &swap_opened).unwrap();
            fs::rename(&swap_replacement, &swap_home).unwrap();
        });
        reset_authorized_mutation_count();

        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| Ok(true),
        );

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(authorized_mutation_count(), 1);
        let replacement_at_selected_home =
            get_trust_store_file_path(&home_path, &member_handle(ALICE_MEMBER_HANDLE));
        assert_eq!(
            fs::read(replacement_at_selected_home).unwrap(),
            replacement_bytes
        );
        fs::rename(&home_path, &replacement_home).unwrap();
        fs::rename(&opened_home, &home_path).unwrap();
    });

    fs::rename(&external_workspace, temp_dir.path().join("workspace")).unwrap();
}

/// The reviewed trust state is re-read through the trust directory the command
/// opened, the same directory a trust store write of the same command lands in.
/// A directory moved into that path afterwards names something the review never
/// saw, so the check keeps reading the one it was bound to.
#[cfg(unix)]
#[test]
fn test_reviewed_set_plan_keeps_trust_check_bound_to_opened_trust_directory() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let plan = evaluate_write_plan(&execution, None, true);
        let trust_dir = temp_dir.path().join("trust");
        let opened_trust = temp_dir.path().join("trust.opened");
        fs::rename(&trust_dir, &opened_trust).unwrap();
        fs::create_dir(&trust_dir).unwrap();
        fs::set_permissions(&trust_dir, fs::Permissions::from_mode(0o700)).unwrap();

        plan.ensure_current_after_confirmation().unwrap();

        assert!(opened_trust
            .join(format!("{ALICE_MEMBER_HANDLE}.json"))
            .exists());
    });
}

#[test]
fn test_execute_existing_set_rechecks_artifact_after_authorized_mutation() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        let reviewed = evaluate_write_plan(&execution, None, true);
        let path = resolve_test_kv_target_path(&options, None).unwrap();
        let concurrent_path = path.clone();
        set_post_authorized_mutation_hook(move || {
            fs::write(concurrent_path, "post-mutation artifact").unwrap();
        });
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| panic!("approved recipient set must not prompt"),
        )
        .expect_err("artifact change after mutation generation must stop replacement");

        assert!(error.to_string().contains("changed since review"));
        assert_eq!(authorized_mutation_count(), 1);
        assert_eq!(fs::read_to_string(path).unwrap(), "post-mutation artifact");
    });
}

/// The bytes are staged before the name is repointed at them, and a target
/// replaced in that last moment is refused there rather than overwritten.
#[cfg(unix)]
#[test]
fn test_execute_existing_set_rejects_artifact_replaced_before_publish() {
    use crate::support::fs::relative::set_pre_publish_hook;

    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "old")]).unwrap();
        let reviewed = evaluate_write_plan(&execution, None, true);
        let path = resolve_test_kv_target_path(&options, None).unwrap();
        let concurrent_path = path.clone();
        set_pre_publish_hook(move || {
            fs::write(concurrent_path, "pre-publish artifact").unwrap();
        });

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "new")],
            |_, _| panic!("approved recipient set must not prompt"),
        )
        .expect_err("an artifact replaced before the rename must stop replacement");

        assert!(error.to_string().contains("changed since review"));
        assert_eq!(fs::read_to_string(path).unwrap(), "pre-publish artifact");
    });
}

#[test]
fn test_reevaluate_set_plan_rejects_artifact_change_after_review() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let reviewed_missing = evaluate_write_plan(&execution, None, true);
        let concurrent = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&concurrent, vec![kv_input("EXTERNAL", "change")]).unwrap();

        let error = match reevaluate_mutation_write_plan_after_review(reviewed_missing) {
            Err(error) => error,
            Ok(_) => panic!("expected artifact snapshot mismatch error"),
        };
        assert!(error.to_string().contains("KV file changed since review"));
    });
}

#[test]
fn test_reevaluate_set_plan_rejects_active_member_change_after_review() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let bob_active = workspace_dir
            .join("members")
            .join("active")
            .join(format!("{}.json", BOB_MEMBER_HANDLE));
        let bob_incoming = workspace_dir
            .join("members")
            .join("incoming")
            .join(format!("{}.json", BOB_MEMBER_HANDLE));
        fs::rename(bob_active, bob_incoming).unwrap();

        let error = match reevaluate_mutation_write_plan_after_review(reviewed) {
            Err(error) => error,
            Ok(_) => panic!("expected active member snapshot mismatch error"),
        };
        assert!(error
            .to_string()
            .contains("KV active members changed since review"));
    });
}

#[test]
fn test_execute_set_updates_existing_key_value() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("API_KEY", "initial_value")])
            .unwrap();

        let update = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&update, vec![kv_input("API_KEY", "updated_value")])
            .unwrap();

        let values = read_kv_values(&options, KvReadMode::Single("API_KEY"));
        assert_eq!(
            values.get("API_KEY").map(String::as_str),
            Some("updated_value")
        );
    });
}

#[test]
fn test_execute_set_preserves_existing_keys_when_adding_entry() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "value1")]).unwrap();

        let update = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&update, vec![kv_input("KEY2", "value2")]).unwrap();

        let values = read_kv_values(&options, KvReadMode::All);
        assert_eq!(values.get("KEY1").map(String::as_str), Some("value1"));
        assert_eq!(values.get("KEY2").map(String::as_str), Some("value2"));
    });
}

#[test]
fn test_import_kv_overwrites_existing_key() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("API_KEY", "old_value")]).unwrap();

        let import = evaluate_write_plan(&execution, None, true);
        let imported = import_kv_command_with_recipient_set_confirmation(
            &import,
            "API_KEY=new_value\n",
            |_, _| Ok(true),
        )
        .unwrap();

        let values = read_kv_values(&options, KvReadMode::Single("API_KEY"));
        assert_eq!(imported, 1);
        assert_eq!(values.get("API_KEY").map(String::as_str), Some("new_value"));
    });
}

#[test]
fn test_execute_set_rejects_unreviewed_output_member_set_non_interactive() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let mut reviewed = evaluate_write_plan(&execution, None, true);
        reviewed.trust_context.review_available = false;
        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "value1")],
            |_, _| Ok(true),
        );

        let error = result.expect_err("expected missing recipient set review error");
        assert_eq!(error.kind(), crate::ErrorKind::Verify);
        assert_eq!(error.rule(), Some("E_RECIPIENT_TRUST_MISSING"));
        assert!(!kv_path.exists());
    });
}

#[test]
fn test_execute_unset_keeps_the_file_when_recipient_set_approval_save_fails() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "value1")]).unwrap();
        remove_approved_recipient_set(&options);
        let reviewed = evaluate_write_plan(&execution, None, false);
        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        let reviewed_content = fs::read_to_string(&kv_path).unwrap();
        let mut confirmations = 0;
        fail_next_trust_store_save();

        let result = unset_kv_command_with_recipient_set_confirmation(&reviewed, "KEY1", |_, _| {
            confirmations += 1;
            Ok(true)
        });

        let error = result.expect_err("expected injected trust store save failure");
        assert_eq!(confirmations, 1);
        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert!(error
            .to_string()
            .contains("Injected trust store save failure"));
        assert_eq!(fs::read_to_string(&kv_path).unwrap(), reviewed_content);
    });
}

#[test]
fn test_execute_set_rejects_existing_file_mismatch_after_review() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "value1")]).unwrap();

        let reviewed = evaluate_write_plan(&execution, None, true);
        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        fs::write(&kv_path, ":KAPSARO_KV 1\n:HEAD {}\n:WRAP {}\n").unwrap();

        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY2", "value2")],
            |_, _| Ok(false),
        );

        match result {
            Err(err) => assert!(err.to_string().contains("changed since review")),
            Ok(_) => panic!("expected mismatch error"),
        }
        assert_eq!(
            fs::read_to_string(&kv_path).unwrap(),
            ":KAPSARO_KV 1\n:HEAD {}\n:WRAP {}\n"
        );
    });
}

#[test]
fn test_resolve_set_plan_rejects_existing_artifact_with_inactive_recipient() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "value1")]).unwrap();
        fs::remove_file(
            workspace_dir
                .join("members")
                .join("active")
                .join(format!("{}.json", BOB_MEMBER_HANDLE)),
        )
        .unwrap();

        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let result = resolve_mutation_write_plan(
            &execution.directories,
            &execution.trust,
            execution.options,
            None,
            true,
        );

        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("expected inactive recipient error"),
        };
        assert_eq!(error.kind(), crate::ErrorKind::Verify);
        assert_eq!(error.rule(), Some("E_ARTIFACT_RECIPIENT_NOT_ACTIVE"));
        assert!(error.format_user_message().contains("rewrap"));
    });
}

#[test]
fn test_execute_set_rejects_file_created_after_missing_review() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let reviewed = evaluate_write_plan(&execution, Some("later"), true);
        let kv_path = workspace_dir.join("secrets").join("later.kvenc");
        fs::write(&kv_path, "external-content").unwrap();

        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "value1")],
            |_, _| Ok(false),
        );

        match result {
            Err(err) => assert!(err.to_string().contains("changed since review")),
            Ok(_) => panic!("expected mismatch error"),
        }
        assert_eq!(fs::read_to_string(&kv_path).unwrap(), "external-content");
    });
}

#[cfg(unix)]
#[test]
fn test_execute_set_rejects_symlinked_existing_file_after_review() {
    use std::os::unix::fs::symlink;

    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "value1")]).unwrap();

        let reviewed = evaluate_write_plan(&execution, None, true);
        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        let reviewed_content = fs::read_to_string(&kv_path).unwrap();
        let victim_path = workspace_dir.join("victim.kvenc");
        fs::write(&victim_path, &reviewed_content).unwrap();
        fs::remove_file(&kv_path).unwrap();
        symlink(&victim_path, &kv_path).unwrap();

        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY2", "value2")],
            |_, _| Ok(false),
        );

        match result {
            Err(err) => assert!(err.to_string().contains("changed since review")),
            Ok(_) => panic!("expected mismatch error"),
        }
        assert_eq!(fs::read_to_string(&victim_path).unwrap(), reviewed_content);
    });
}

#[test]
fn test_execute_set_rejects_active_member_snapshot_change_after_review() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let bob_active = workspace_dir
            .join("members")
            .join("active")
            .join(format!("{}.json", BOB_MEMBER_HANDLE));
        let bob_incoming = workspace_dir
            .join("members")
            .join("incoming")
            .join(format!("{}.json", BOB_MEMBER_HANDLE));
        fs::rename(&bob_active, &bob_incoming).unwrap();

        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "value1")],
            |_, _| Ok(false),
        );

        match result {
            Err(err) => assert!(err
                .to_string()
                .contains("active members changed since review")),
            Ok(_) => panic!("expected active member snapshot mismatch error"),
        }
    });
}

#[test]
fn test_execute_set_rejects_resigned_trust_store_change_after_review() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let reviewed = evaluate_write_plan(&execution, None, true);
        let bob_kid = list_kids(&temp_dir.path().join("keys"), BOB_MEMBER_HANDLE)
            .unwrap()
            .remove(0);

        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![kv_input("KEY1", "value1")],
            |_, _| {
                let trust =
                    build_test_trust_command_session_from_options(&options, ALICE_MEMBER_HANDLE);
                remove_known_key_command(&trust, &bob_kid)?;
                Ok(true)
            },
        );

        let error = result.expect_err("expected trust store snapshot mismatch error");
        assert!(error
            .to_string()
            .contains("trust store changed since review"));
        assert!(!kv_path.exists());
    });
}

#[test]
fn test_evaluate_set_rejects_strict_key_checking_no_for_existing_file() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let initial = evaluate_write_plan(&execution, None, true);
        set_kv_with_approved_member_set(&initial, vec![kv_input("KEY1", "value1")]).unwrap();
        let result = resolve_mutation_write_plan(
            &execution.directories,
            &execution.trust,
            crate::service::trust::WriteTrustOptions::new(
                false,
                true,
                crate::service::trust::StrictKeyCheckingResolution::explicit(
                    crate::service::trust::StrictKeyChecking::No,
                ),
            ),
            None,
            true,
        );

        match result {
            Err(err) => assert!(err.to_string().contains("cannot be disabled")),
            Ok(_) => panic!("expected strict key checking error"),
        }
    });
}

/// A group-readable trust store exposes local state, so planning a KV write
/// carries on and names the file that must be repaired.
#[cfg(unix)]
#[test]
fn test_evaluate_kv_write_trust_warns_about_insecure_trust_store() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let warning_guard = LocalStateWarningGuard::new();
    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        resolve_mutation_write_plan(
            &execution.directories,
            &execution.trust,
            execution.options,
            None,
            true,
        )
        .unwrap();
    });
    let warnings = warning_guard.take_reasons();

    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("Insecure permissions 0644"),
        "{warnings:?}"
    );
    assert!(warnings[0].contains("chmod 0600"), "{warnings:?}");
}

#[test]
fn test_resolve_mutation_write_plan_includes_private_key_expiry_warning() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_HANDLE, &expires_at);

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let plan = evaluate_write_plan(&execution, None, true);
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("Local key expires in")));
    });
}

#[test]
fn test_resolve_mutation_write_plan_includes_recipient_key_expiry_warning() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), BOB_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, BOB_MEMBER_HANDLE)
        .unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
        let plan = evaluate_write_plan(&execution, None, true);
        assert!(plan.warnings.iter().any(|warning| {
            warning.contains("Recipient public key for 'bob@example.com' expires in")
        }));
    });
}
