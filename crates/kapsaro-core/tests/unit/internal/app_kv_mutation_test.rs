// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::api::key::LocalKeyStore;
use crate::api::kv::{KvEncArtifact, KvReadOperation};
use crate::api::trust::{
    CurrentMemberSnapshot, LocalTrustStore, TrustApproval, TrustDecision, TrustPolicyEvaluator,
};
use crate::app::context::execution::resolve_read_execution;
use crate::app::context::options::CommonCommandOptions;
use crate::app::kv::mutation::{
    authorized_mutation_count, import_kv_command_with_recipient_set_confirmation,
    reevaluate_mutation_write_plan_after_review, reset_authorized_mutation_count,
    resolve_mutation_write_plan, set_kv_command_with_recipient_set_confirmation,
    set_post_authorized_mutation_hook, set_post_recipient_approval_hook,
    unset_kv_command_with_recipient_set_confirmation, MutationWriteTrustPlan,
};
use crate::app::kv::query::resolve_kv_read_path;
use crate::app::kv::types::KvInputEntry;
use crate::app::trust::management::{remove_known_key_command, remove_recipient_set_command};
use crate::app::trust::review::{
    review_write_recipient_trust, TrustExecutionContext, WriteRecipientTrustReviewPlan,
};
use crate::app::trust::{ImportPolicy, SetPolicy, UnsetPolicy, WriteTrustPolicy};
use crate::app_test_utils::{build_test_signing_command_options, resolve_test_ssh_context};
use crate::io::keystore::active::set_active_kid;
use crate::io::keystore::storage::list_kids;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::fail_next_trust_store_save;
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace, setup_member_key_context,
    setup_test_workspace_from_fixtures, setup_trust_store_for_workspace,
    update_active_private_key_expires_at, with_temp_cwd, EnvGuard,
};
use std::fs;

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";

#[derive(Clone, Copy)]
enum KvReadMode<'a> {
    All,
    Single(&'a str),
}

struct InteractiveOverrideGuard;

impl InteractiveOverrideGuard {
    fn enable() -> Self {
        crate::support::tty::set_interactive_override(Some(true));
        Self
    }
}

impl Drop for InteractiveOverrideGuard {
    fn drop(&mut self) {
        crate::support::tty::set_interactive_override(None);
    }
}

fn evaluate_set_plan(
    options: &CommonCommandOptions,
    name: Option<&str>,
) -> MutationWriteTrustPlan<SetPolicy> {
    let ssh_ctx = Some(resolve_test_ssh_context(options, ALICE_MEMBER_HANDLE));
    resolve_mutation_write_plan::<SetPolicy>(
        options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        name,
        true,
        ssh_ctx,
    )
    .unwrap()
}

fn evaluate_unset_plan(
    options: &CommonCommandOptions,
    name: Option<&str>,
) -> MutationWriteTrustPlan<UnsetPolicy> {
    let ssh_ctx = Some(resolve_test_ssh_context(options, ALICE_MEMBER_HANDLE));
    resolve_mutation_write_plan::<UnsetPolicy>(
        options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        name,
        false,
        ssh_ctx,
    )
    .unwrap()
}

fn evaluate_import_plan(
    options: &CommonCommandOptions,
    name: Option<&str>,
) -> MutationWriteTrustPlan<ImportPolicy> {
    let ssh_ctx = Some(resolve_test_ssh_context(options, ALICE_MEMBER_HANDLE));
    resolve_mutation_write_plan::<ImportPolicy>(
        options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        name,
        true,
        ssh_ctx,
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

fn allow_member_set_review<P>(plan: &mut MutationWriteTrustPlan<P>) {
    plan.trust_context.is_interactive = true;
}

fn read_kv_values(
    options: &CommonCommandOptions,
    mode: KvReadMode<'_>,
) -> std::collections::BTreeMap<String, String> {
    let ssh_ctx = Some(resolve_test_ssh_context(options, ALICE_MEMBER_HANDLE));
    let execution = resolve_read_execution(
        options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        ssh_ctx,
    )
    .unwrap();
    let artifact = KvEncArtifact::load(resolve_kv_read_path(options, None).unwrap()).unwrap();
    let verified = artifact.verify(options.operation_options()).unwrap();
    let members = CurrentMemberSnapshot::load(options.workspace.as_ref().unwrap()).unwrap();
    let key_store = LocalKeyStore::new(options.resolve_keystore_root().unwrap());
    let trust_store = LocalTrustStore::new(
        options.resolve_base_dir().unwrap(),
        ALICE_MEMBER_HANDLE.to_string(),
    );
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
            &execution.key_ctx,
            operation,
            options.operation_options(),
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

fn set_kv_with_approved_member_set<P>(
    plan: &MutationWriteTrustPlan<P>,
    entries: Vec<KvInputEntry>,
    success_message: Option<&str>,
) -> crate::Result<crate::app::kv::types::KvWriteOutcome>
where
    P: crate::app::trust::WriteTrustPolicy,
{
    set_kv_command_with_recipient_set_confirmation(plan, entries, success_message, |_, _| Ok(true))
}

fn unset_kv_with_approved_member_set<P>(
    plan: &MutationWriteTrustPlan<P>,
    key: &str,
    success_message: Option<&str>,
) -> crate::Result<crate::app::kv::types::KvWriteOutcome>
where
    P: crate::app::trust::WriteTrustPolicy,
{
    unset_kv_command_with_recipient_set_confirmation(plan, key, success_message, |_, _| Ok(true))
}

fn approve_recipient_keys_and_reevaluate<P>(
    options: &CommonCommandOptions,
    plan: MutationWriteTrustPlan<P>,
) -> MutationWriteTrustPlan<P>
where
    P: WriteTrustPolicy,
{
    review_write_recipient_trust(
        TrustExecutionContext {
            options,
            execution: &plan.execution,
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

fn remove_bob_known_key<P>(
    options: &CommonCommandOptions,
    plan: &MutationWriteTrustPlan<P>,
    home: &std::path::Path,
) {
    let bob_kid = list_kids(&home.join("keys"), BOB_MEMBER_HANDLE)
        .unwrap()
        .remove(0);
    remove_known_key_command(options, &plan.execution, &bob_kid).unwrap();
}

fn remove_approved_recipient_set<P>(
    options: &CommonCommandOptions,
    plan: &MutationWriteTrustPlan<P>,
) {
    let path = resolve_kv_read_path(options, None).unwrap();
    let artifact = KvEncArtifact::load(path).unwrap();
    let sid = artifact
        .verify(options.operation_options())
        .unwrap()
        .recipient_set_subject()
        .unwrap()
        .sid()
        .to_string();
    remove_recipient_set_command(options, &plan.execution, &sid).unwrap();
}

#[test]
fn test_execute_set_creates_default_kv_file_with_entry() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let mut plan = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut plan);

        set_kv_with_approved_member_set(
            &plan,
            vec![KvInputEntry::new("DATABASE_URL", "postgres://localhost/db")],
            None,
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
        let _interactive = InteractiveOverrideGuard::enable();
        let plan = evaluate_set_plan(&options, None);
        let plan = approve_recipient_keys_and_reevaluate(&options, plan);

        set_kv_with_approved_member_set(
            &plan,
            vec![KvInputEntry::new("DATABASE_URL", "postgres://localhost/db")],
            None,
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
        let _interactive = InteractiveOverrideGuard::enable();
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "value1")], None)
            .unwrap();
        remove_bob_known_key(&options, &initial, temp_dir.path());

        let plan = evaluate_unset_plan(&options, None);
        let plan = approve_recipient_keys_and_reevaluate(&options, plan);
        unset_kv_with_approved_member_set(&plan, "KEY1", None).unwrap();

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
        let _interactive = InteractiveOverrideGuard::enable();
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "old")], None)
            .unwrap();
        remove_bob_known_key(&options, &initial, temp_dir.path());

        let plan = evaluate_import_plan(&options, None);
        let plan = approve_recipient_keys_and_reevaluate(&options, plan);
        let (_, imported) = import_kv_command_with_recipient_set_confirmation(
            &plan,
            "KEY1=new\nKEY2=added\n",
            None,
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
        let _interactive = InteractiveOverrideGuard::enable();
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "old")], None)
            .unwrap();
        remove_approved_recipient_set(&options, &initial);
        let mut reviewed = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut reviewed);
        reset_authorized_mutation_count();
        let mut confirmations = 0;

        set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "new")],
            None,
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
        let _interactive = InteractiveOverrideGuard::enable();
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "old")], None)
            .unwrap();
        remove_approved_recipient_set(&options, &initial);
        let mut reviewed = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut reviewed);
        let path = resolve_kv_read_path(&options, None).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "new")],
            None,
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
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "old")], None)
            .unwrap();
        remove_approved_recipient_set(&options, &initial);
        let mut reviewed = evaluate_set_plan(&options, None);
        reviewed.trust_context.is_interactive = false;
        let path = resolve_kv_read_path(&options, None).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "new")],
            None,
            |_, _| panic!("non-interactive review must not prompt"),
        )
        .expect_err("missing recipient set must preserve its stable error");

        assert_eq!(error.verification_rule(), Some("E_RECIPIENT_TRUST_MISSING"));
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
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "old")], None)
            .unwrap();
        let path = resolve_kv_read_path(&options, None).unwrap();
        let artifact = KvEncArtifact::load(&path).unwrap();
        let sid = artifact
            .verify(options.operation_options())
            .unwrap()
            .recipient_set_subject()
            .unwrap()
            .sid();
        let alice_kid = LocalKeyStore::new(temp_dir.path().join("keys"))
            .load_active_kid(ALICE_MEMBER_HANDLE)
            .unwrap()
            .unwrap();
        LocalTrustStore::new(temp_dir.path(), ALICE_MEMBER_HANDLE.to_string())
            .apply_approvals(
                vec![TrustApproval::recipient_set(sid, vec![alice_kid])],
                &initial.execution.key_ctx,
            )
            .unwrap();
        let mut reviewed = evaluate_set_plan(&options, None);
        reviewed.trust_context.is_interactive = false;
        let before = fs::read_to_string(&path).unwrap();
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "new")],
            None,
            |_, _| panic!("non-interactive review must not prompt"),
        )
        .expect_err("changed recipient set must preserve its stable error");

        assert_eq!(error.verification_rule(), Some("E_RECIPIENT_SET_CHANGED"));
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
        let _interactive = InteractiveOverrideGuard::enable();
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "old")], None)
            .unwrap();
        remove_approved_recipient_set(&options, &initial);
        let mut reviewed = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut reviewed);
        let path = resolve_kv_read_path(&options, None).unwrap();
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "new")],
            None,
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
        let _interactive = InteractiveOverrideGuard::enable();
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "old")], None)
            .unwrap();
        remove_approved_recipient_set(&options, &initial);
        let mut reviewed = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut reviewed);
        let path = resolve_kv_read_path(&options, None).unwrap();
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
            vec![KvInputEntry::new("KEY1", "new")],
            None,
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
        let _interactive = InteractiveOverrideGuard::enable();
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "old")], None)
            .unwrap();
        remove_approved_recipient_set(&options, &initial);
        let mut reviewed = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut reviewed);
        let path = resolve_kv_read_path(&options, None).unwrap();
        let concurrent_path = path.clone();
        set_post_recipient_approval_hook(move || {
            fs::write(concurrent_path, "post-approval artifact").unwrap();
        });
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "new")],
            None,
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
        let _interactive = InteractiveOverrideGuard::enable();
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "old")], None)
            .unwrap();
        remove_approved_recipient_set(&options, &initial);
        let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_HANDLE);
        let pre_approval_trust = fs::read_to_string(&trust_path).unwrap();
        let mut reviewed = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut reviewed);
        let path = resolve_kv_read_path(&options, None).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        set_post_recipient_approval_hook(move || {
            fs::write(trust_path, pre_approval_trust).unwrap();
        });
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "new")],
            None,
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
        let _interactive = InteractiveOverrideGuard::enable();
        let mut reviewed = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut reviewed);
        let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_HANDLE);
        let pre_approval_trust = fs::read_to_string(&trust_path).unwrap();
        let path = workspace_dir.join("secrets").join("default.kvenc");
        set_post_recipient_approval_hook(move || {
            fs::write(trust_path, pre_approval_trust).unwrap();
        });
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "value1")],
            None,
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
fn test_execute_existing_set_rechecks_artifact_after_authorized_mutation() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "old")], None)
            .unwrap();
        let reviewed = evaluate_set_plan(&options, None);
        let path = resolve_kv_read_path(&options, None).unwrap();
        let concurrent_path = path.clone();
        set_post_authorized_mutation_hook(move || {
            fs::write(concurrent_path, "post-mutation artifact").unwrap();
        });
        reset_authorized_mutation_count();

        let error = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "new")],
            None,
            |_, _| panic!("approved recipient set must not prompt"),
        )
        .expect_err("artifact change after mutation generation must stop replacement");

        assert!(error.to_string().contains("changed since review"));
        assert_eq!(authorized_mutation_count(), 1);
        assert_eq!(fs::read_to_string(path).unwrap(), "post-mutation artifact");
    });
}

#[test]
fn test_reevaluate_set_plan_rejects_artifact_change_after_review() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let reviewed_missing = evaluate_set_plan(&options, None);
        let mut concurrent = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut concurrent);
        set_kv_with_approved_member_set(
            &concurrent,
            vec![KvInputEntry::new("EXTERNAL", "change")],
            None,
        )
        .unwrap();

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
        let reviewed = evaluate_set_plan(&options, None);
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
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(
            &initial,
            vec![KvInputEntry::new("API_KEY", "initial_value")],
            None,
        )
        .unwrap();

        let mut update = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut update);
        set_kv_with_approved_member_set(
            &update,
            vec![KvInputEntry::new("API_KEY", "updated_value")],
            None,
        )
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
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "value1")], None)
            .unwrap();

        let mut update = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut update);
        set_kv_with_approved_member_set(&update, vec![KvInputEntry::new("KEY2", "value2")], None)
            .unwrap();

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
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(
            &initial,
            vec![KvInputEntry::new("API_KEY", "old_value")],
            None,
        )
        .unwrap();

        let mut import = evaluate_import_plan(&options, None);
        allow_member_set_review(&mut import);
        let (_, imported) = import_kv_command_with_recipient_set_confirmation(
            &import,
            "API_KEY=new_value\n",
            None,
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
        let mut reviewed = evaluate_set_plan(&options, None);
        reviewed.trust_context.is_interactive = false;
        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "value1")],
            None,
            |_, _| Ok(true),
        );

        let error = result.expect_err("expected missing recipient set review error");
        assert_eq!(error.kind(), crate::ErrorKind::Verify);
        assert_eq!(error.verification_rule(), Some("E_RECIPIENT_TRUST_MISSING"));
        assert!(!kv_path.exists());
    });
}

#[test]
fn test_execute_unset_does_not_replace_file_when_recipient_set_approval_save_fails() {
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
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "value1")], None)
            .unwrap();
        remove_approved_recipient_set(&options, &initial);
        let mut reviewed = evaluate_unset_plan(&options, None);
        allow_member_set_review(&mut reviewed);
        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        let reviewed_content = fs::read_to_string(&kv_path).unwrap();
        let mut confirmations = 0;
        fail_next_trust_store_save();

        let result =
            unset_kv_command_with_recipient_set_confirmation(&reviewed, "KEY1", None, |_, _| {
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
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "value1")], None)
            .unwrap();

        let reviewed = evaluate_set_plan(&options, None);
        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        fs::write(&kv_path, ":KAPSARO_KV 1\n:HEAD {}\n:WRAP {}\n").unwrap();

        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY2", "value2")],
            None,
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
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "value1")], None)
            .unwrap();
        fs::remove_file(
            workspace_dir
                .join("members")
                .join("active")
                .join(format!("{}.json", BOB_MEMBER_HANDLE)),
        )
        .unwrap();

        let result = resolve_mutation_write_plan::<SetPolicy>(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
            true,
            Some(resolve_test_ssh_context(&options, ALICE_MEMBER_HANDLE)),
        );

        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("expected inactive recipient error"),
        };
        assert_eq!(error.kind(), crate::ErrorKind::Verify);
        assert_eq!(
            error.verification_rule(),
            Some("E_ARTIFACT_RECIPIENT_NOT_ACTIVE")
        );
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
        let reviewed = evaluate_set_plan(&options, Some("later"));
        let kv_path = workspace_dir.join("secrets").join("later.kvenc");
        fs::write(&kv_path, "external-content").unwrap();

        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "value1")],
            None,
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
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "value1")], None)
            .unwrap();

        let reviewed = evaluate_set_plan(&options, None);
        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        let reviewed_content = fs::read_to_string(&kv_path).unwrap();
        let victim_path = workspace_dir.join("victim.kvenc");
        fs::write(&victim_path, &reviewed_content).unwrap();
        fs::remove_file(&kv_path).unwrap();
        symlink(&victim_path, &kv_path).unwrap();

        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY2", "value2")],
            None,
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
        let reviewed = evaluate_set_plan(&options, None);
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
            vec![KvInputEntry::new("KEY1", "value1")],
            None,
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
        let mut reviewed = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut reviewed);
        let bob_kid = list_kids(&temp_dir.path().join("keys"), BOB_MEMBER_HANDLE)
            .unwrap()
            .remove(0);

        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        let result = set_kv_command_with_recipient_set_confirmation(
            &reviewed,
            vec![KvInputEntry::new("KEY1", "value1")],
            None,
            |_, _| {
                remove_known_key_command(&options, &reviewed.execution, &bob_kid)?;
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
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let mut initial = evaluate_set_plan(&options, None);
        allow_member_set_review(&mut initial);
        set_kv_with_approved_member_set(&initial, vec![KvInputEntry::new("KEY1", "value1")], None)
            .unwrap();
        std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "no");

        let ssh_ctx = Some(resolve_test_ssh_context(&options, ALICE_MEMBER_HANDLE));
        let result = resolve_mutation_write_plan::<SetPolicy>(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
            true,
            ssh_ctx,
        );

        match result {
            Err(err) => assert!(err.to_string().contains("not allowed")),
            Ok(_) => panic!("expected strict key checking error"),
        }
    });
}

#[cfg(unix)]
#[test]
fn test_evaluate_kv_write_trust_surfaces_insecure_trust_store_warning() {
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
    let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_HANDLE);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    with_temp_cwd(temp_dir.path(), || {
        let plan = evaluate_set_plan(&options, None);
        assert!(!plan.warnings.is_empty());
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("Insecure permissions")));
    });
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
        let plan = evaluate_set_plan(&options, None);
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
        let plan = evaluate_set_plan(&options, None);
        assert!(plan.warnings.iter().any(
            |warning| warning.contains("Recipient public key for 'bob@example.com' expires in")
        ));
    });
}
