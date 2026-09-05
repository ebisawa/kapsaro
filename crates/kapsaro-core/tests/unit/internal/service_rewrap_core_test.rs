// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for the operation-bound rewrap capability.
//! Covers both artifact formats and fail-closed post-promotion member checks.

use std::fs;

use super::{
    RewrapOptions, RewrapParentBinding, RewrapSession, RewrapSessionDecision, RewrapTarget,
};
use crate::api::file::FileEncArtifact;
use crate::api::key::{KeyContext, LocalKeyStore, MemberHandle, RecipientKeys};
use crate::api::kv::{KvEncArtifact, KvInputEntry};
use crate::api::operation::OperationOptions;
use crate::api::secret::SecretString;
use crate::api::trust::{
    CurrentMemberSnapshot, KnownKeyApprovalEvidence, TrustApproval, TrustCommandSession,
    TrustDecision, TrustPolicyEvaluator,
};
use crate::support::fs::relative::set_pre_publish_hook;
use crate::test_utils::{setup_member_key_context, setup_test_workspace_from_fixtures};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";

fn member(value: &str) -> MemberHandle {
    MemberHandle::try_from(value).unwrap()
}

fn setup_self() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    KeyContext,
    crate::api::key::RecipientKeys,
) {
    let (temp, workspace) = setup_test_workspace_from_fixtures(&[ALICE]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&temp, ALICE, None));
    let recipients = LocalKeyStore::open(temp.path().join("keys"))
        .unwrap()
        .load_recipient_keys([member(ALICE)])
        .unwrap();
    (temp, workspace, key_ctx, recipients)
}

#[test]
fn test_rewrap_target_missing_entry_error() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing.json");

    let error = match RewrapTarget::open(&missing) {
        Ok(_) => panic!("a missing target must be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
    assert!(error.format_user_message().contains("no such file"));
}

#[test]
fn test_rewrap_target_non_regular_entry_error() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("artifact.json");
    fs::create_dir(&directory).unwrap();

    let error = match RewrapTarget::open(&directory) {
        Ok(_) => panic!("a directory must not become a rewrap target"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(error.format_user_message().contains("non-regular file"));
}

#[cfg(unix)]
#[test]
fn test_rewrap_target_identity_uses_directory_and_entry_name() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("targets");
    fs::create_dir(&directory).unwrap();
    let original = directory.join("artifact.json");
    let hardlink = directory.join("artifact-hardlink.json");
    fs::write(&original, "artifact").unwrap();
    fs::hard_link(&original, &hardlink).unwrap();

    let direct = RewrapTarget::open(&original).unwrap();
    let alternate_spelling = RewrapTarget::open(directory.join(".").join("artifact.json")).unwrap();
    let distinct_hardlink = RewrapTarget::open(&hardlink).unwrap();

    assert!(direct == alternate_spelling);
    assert!(direct != distinct_hardlink);
}

#[cfg(unix)]
#[test]
fn test_rewrap_target_identity_resolves_parent_components() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("nested")).unwrap();
    let artifact = root.path().join("artifact.json");
    fs::write(&artifact, "artifact").unwrap();

    let direct = RewrapTarget::open(&artifact).unwrap();
    let parent_spelling = RewrapTarget::open(root.path().join("nested/../artifact.json")).unwrap();

    assert!(direct == parent_spelling);
    assert_eq!(
        parent_spelling.path(),
        root.path().join("nested/../artifact.json")
    );
}

#[cfg(unix)]
#[test]
fn test_rewrap_target_identity_preserves_os_symlink_parent_resolution() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let resolved = root.path().join("resolved");
    let nested = resolved.join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(resolved.join("artifact.json"), "resolved artifact").unwrap();
    fs::write(root.path().join("artifact.json"), "lexical artifact").unwrap();
    symlink(&nested, root.path().join("alias")).unwrap();

    let os_resolved = RewrapTarget::open(root.path().join("alias/../artifact.json")).unwrap();
    let direct = RewrapTarget::open(resolved.join("artifact.json")).unwrap();
    let lexical = RewrapTarget::open(root.path().join("artifact.json")).unwrap();

    assert!(os_resolved == direct);
    assert!(os_resolved != lexical);
}

#[cfg(unix)]
#[test]
fn test_rewrap_target_root_parent_missing_entry_error() {
    let missing =
        std::path::Path::new("/").join(format!(".kapsaro-rewrap-missing-{}", uuid::Uuid::new_v4()));

    let error = match RewrapTarget::open(&missing) {
        Ok(_) => panic!("a missing target below the fixed root must be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
}

#[cfg(unix)]
#[test]
fn test_rewrap_root_parent_binding_uses_fixed_directory() {
    use crate::support::fs::relative::{open_dir_nofollow, DirectoryScope};
    use std::sync::Arc;

    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    let moved = outer.path().join("moved");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("artifact.json"), "artifact").unwrap();
    let dir = Arc::new(open_dir_nofollow(&root, DirectoryScope::Generic).unwrap());
    let target = RewrapTarget::from_fixed_parent(
        RewrapParentBinding::Root,
        dir,
        "artifact.json".to_string(),
        root.join("artifact.json"),
    )
    .unwrap();
    fs::rename(&root, &moved).unwrap();

    target.ensure_parent_current().unwrap();
    assert_eq!(
        fs::read_to_string(moved.join("artifact.json")).unwrap(),
        "artifact"
    );
}

#[test]
fn test_file_rewrap_requires_and_uses_authorized_capability() {
    let (_temp, workspace, key_ctx, recipients) = setup_self();
    let verified = FileEncArtifact::encrypt_bytes(b"secret", &recipients, &key_ctx)
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap();
    let evaluator =
        TrustPolicyEvaluator::new(CurrentMemberSnapshot::load(&workspace).unwrap(), None);

    let TrustDecision::Trusted(authorized) = evaluator
        .evaluate_rewrap(
            &evaluator,
            verified,
            recipients,
            &key_ctx,
            RewrapOptions::new().with_rotate_key(true),
            None,
        )
        .unwrap()
    else {
        panic!("self-only file rewrap must be authorized");
    };

    let rewritten = authorized.rewrite().unwrap();
    FileEncArtifact::parse(rewritten)
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap();
}

#[test]
fn test_kv_rewrap_requires_and_uses_authorized_capability() {
    let (_temp, workspace, key_ctx, recipients) = setup_self();
    let verified = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "SECRET",
            SecretString::new("value".to_string()),
        )],
        &recipients,
        &key_ctx,
    )
    .unwrap()
    .verify(OperationOptions::default())
    .unwrap();
    let evaluator =
        TrustPolicyEvaluator::new(CurrentMemberSnapshot::load(&workspace).unwrap(), None);

    let TrustDecision::Trusted(authorized) = evaluator
        .evaluate_rewrap(
            &evaluator,
            verified,
            recipients,
            &key_ctx,
            RewrapOptions::new().with_clear_disclosure_history(true),
            None,
        )
        .unwrap()
    else {
        panic!("self-only KV rewrap must be authorized");
    };

    let rewritten = authorized.rewrite().unwrap();
    KvEncArtifact::parse(rewritten)
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap();
}

#[test]
fn test_public_rewrap_session_issues_capabilities_for_both_formats() {
    let (temp, workspace, key_ctx, recipients) = setup_self();
    let file = FileEncArtifact::encrypt_bytes(b"secret", &recipients, &key_ctx).unwrap();
    let kv = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "SECRET",
            SecretString::new("value".to_string()),
        )],
        &recipients,
        &key_ctx,
    )
    .unwrap();
    let secrets = workspace.join("secrets");
    file.save(secrets.join("secret.json")).unwrap();
    kv.save(secrets.join("secret.env.kvenc")).unwrap();
    let trust = TrustCommandSession::from_test_parts(temp.path(), member(ALICE), key_ctx).unwrap();
    let session = RewrapSession::from_trust_command(&workspace, &trust).unwrap();

    assert!(session.signing_key_warnings().unwrap().is_empty());

    let targets = session.list_workspace_targets().unwrap().into_targets();
    assert_eq!(targets.len(), 2);
    let mut file_target = None;
    let mut kv_target = None;
    for target in targets {
        match target.name() {
            "secret.json" => file_target = Some(target),
            "secret.env.kvenc" => kv_target = Some(target),
            other => panic!("unexpected target {other}"),
        }
    }
    let RewrapSessionDecision::Authorized(file) = session
        .begin_rewrap(file_target.unwrap(), RewrapOptions::new(), false)
        .unwrap()
    else {
        panic!("self-only file rewrap must be authorized");
    };
    let RewrapSessionDecision::Authorized(kv) = session
        .begin_rewrap(kv_target.unwrap(), RewrapOptions::new(), false)
        .unwrap()
    else {
        panic!("self-only KV rewrap must be authorized");
    };

    FileEncArtifact::parse(file.rewrite().unwrap())
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap();
    KvEncArtifact::parse(kv.rewrite().unwrap())
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap();
    file.publish().unwrap();
    kv.publish().unwrap();
    FileEncArtifact::load(secrets.join("secret.json"))
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap();
    KvEncArtifact::load(secrets.join("secret.env.kvenc"))
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap();
}

#[test]
fn test_rewrap_session_reuses_post_promotion_recipients_across_targets() {
    let (temp, workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let bob_path = workspace.join("members/active").join(format!("{BOB}.json"));
    let bob_document = fs::read_to_string(&bob_path).unwrap();
    fs::remove_file(&bob_path).unwrap();
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&temp, ALICE, None));
    let recipients = LocalKeyStore::open(temp.path().join("keys"))
        .unwrap()
        .load_recipient_keys([member(ALICE)])
        .unwrap();
    let file = FileEncArtifact::encrypt_bytes(b"secret", &recipients, &key_ctx).unwrap();
    let kv = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "SECRET",
            SecretString::new("value".to_string()),
        )],
        &recipients,
        &key_ctx,
    )
    .unwrap();
    let secrets = workspace.join("secrets");
    file.save(secrets.join("secret.json")).unwrap();
    kv.save(secrets.join("secret.env.kvenc")).unwrap();
    let session = RewrapSession::open(&workspace, None, &key_ctx).unwrap();

    assert!(session.begin_promotion_review(false).unwrap().is_none());
    let RewrapSessionDecision::Authorized(file_authorized) = session
        .begin_rewrap(
            session.workspace_target("secret.json").unwrap(),
            RewrapOptions::new(),
            false,
        )
        .unwrap()
    else {
        panic!("the first target must use the fixed self-only recipient set");
    };
    fs::write(&bob_path, bob_document).unwrap();
    let RewrapSessionDecision::Authorized(kv_authorized) = session
        .begin_rewrap(
            session.workspace_target("secret.env.kvenc").unwrap(),
            RewrapOptions::new(),
            false,
        )
        .unwrap()
    else {
        panic!("the second target must reuse the fixed self-only recipient set");
    };

    let file_subject = FileEncArtifact::parse(file_authorized.rewrite().unwrap())
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap()
        .recipient_set_subject()
        .unwrap();
    let kv_subject = KvEncArtifact::parse(kv_authorized.rewrite().unwrap())
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap()
        .recipient_set_subject()
        .unwrap();
    assert_eq!(
        file_subject.recipient_kids(),
        std::slice::from_ref(key_ctx.kid())
    );
    assert_eq!(kv_subject.recipient_kids(), file_subject.recipient_kids());
}

/// A caller may ask for expiry warnings before it promotes anyone, and that
/// question fixes the recipient set. Promotion has to replace it: a member
/// admitted to the workspace belongs in every artifact the session rewraps,
/// and keeping the earlier answer would leave that member unable to read them.
#[test]
fn test_apply_promotions_replaces_recipients_fixed_before_the_promotion() {
    let (temp, workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let active_bob = workspace.join("members/active").join(format!("{BOB}.json"));
    let incoming = workspace.join("members/incoming");
    fs::create_dir_all(&incoming).unwrap();
    fs::rename(&active_bob, incoming.join(format!("{BOB}.json"))).unwrap();
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&temp, ALICE, None));
    let session =
        RewrapSession::open(&workspace, Some(temp.path().to_path_buf()), &key_ctx).unwrap();

    session.post_promotion_warnings().unwrap();
    let review = session
        .begin_promotion_review(true)
        .unwrap()
        .expect("the incoming member must open a review");
    let outcome = session
        .apply_promotions(review, &[BOB.to_string()])
        .unwrap();

    assert_eq!(
        outcome.promoted_member_handles(),
        [BOB.to_string()].as_slice()
    );
    let recipients = session.ensure_post_promotion_snapshot().unwrap();
    assert!(
        recipients.recipients().handles().contains(&BOB.to_string()),
        "{:?}",
        recipients.recipients().handles()
    );
}

#[test]
fn rewrap_review_rejects_changed_post_promotion_members() {
    let (temp, workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&temp, ALICE, None));
    let recipients = LocalKeyStore::open(temp.path().join("keys"))
        .unwrap()
        .load_recipient_keys([member(ALICE)])
        .unwrap();
    let artifact = FileEncArtifact::encrypt_bytes(b"secret", &recipients, &key_ctx).unwrap();
    let target_path = workspace.join("secrets/secret.json");
    artifact.save(&target_path).unwrap();
    let session = RewrapSession::open(&workspace, None, &key_ctx).unwrap();

    let RewrapSessionDecision::ReviewRequired(review) = session
        .begin_rewrap(
            session.workspace_target("secret.json").unwrap(),
            RewrapOptions::new(),
            false,
        )
        .unwrap()
    else {
        panic!("the unapproved current recipient must require review");
    };
    fs::remove_file(workspace.join("members/active").join(format!("{BOB}.json"))).unwrap();

    let error = match session.resume_rewrap(review, RewrapOptions::new(), None) {
        Ok(RewrapSessionDecision::Authorized(_)) => {
            panic!("changed post-promotion members must not be authorized")
        }
        Ok(RewrapSessionDecision::ReviewRequired(_)) => {
            panic!("changed post-promotion members must invalidate the review")
        }
        Err(error) => error,
    };

    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
    assert_eq!(fs::read_to_string(target_path).unwrap(), artifact.as_str());
}

#[test]
fn test_rewrap_review_member_change_during_approval_error() {
    let (temp, workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&temp, ALICE, None));
    let recipients = LocalKeyStore::open(temp.path().join("keys"))
        .unwrap()
        .load_recipient_keys([member(ALICE)])
        .unwrap();
    let artifact = FileEncArtifact::encrypt_bytes(b"secret", &recipients, &key_ctx).unwrap();
    let target_path = workspace.join("secrets/secret.json");
    artifact.save(&target_path).unwrap();
    let session =
        RewrapSession::open(&workspace, Some(temp.path().to_path_buf()), &key_ctx).unwrap();
    let RewrapSessionDecision::ReviewRequired(mut review) = session
        .begin_rewrap(
            session.workspace_target("secret.json").unwrap(),
            RewrapOptions::new(),
            false,
        )
        .unwrap()
    else {
        panic!("the new Bob recipient key must require review");
    };
    let candidate = review.requests()[0].known_key_candidate().unwrap();
    let approval = TrustApproval::known_key(candidate, KnownKeyApprovalEvidence::none()).unwrap();
    fs::remove_file(workspace.join("members/active").join(format!("{BOB}.json"))).unwrap();

    session
        .apply_review_approval(&mut review, approval)
        .unwrap();
    let error = match session.resume_rewrap(review, RewrapOptions::new(), None) {
        Ok(RewrapSessionDecision::Authorized(_)) => {
            panic!("changed post-promotion members must not be authorized")
        }
        Ok(RewrapSessionDecision::ReviewRequired(_)) => {
            panic!("changed post-promotion members must invalidate the review")
        }
        Err(error) => error,
    };

    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
    assert_eq!(fs::read_to_string(target_path).unwrap(), artifact.as_str());
}

/// A KV review carries the same artifact binding a file review does, so a
/// target rewritten between the review and the resume must be refused.
#[test]
fn test_resume_rewrap_kv_content_changed_error() {
    let (temp, workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&temp, ALICE, None));
    let recipients = LocalKeyStore::open(temp.path().join("keys"))
        .unwrap()
        .load_recipient_keys([member(ALICE)])
        .unwrap();
    let entries = || {
        vec![KvInputEntry::new(
            "SECRET",
            SecretString::new("value".to_string()),
        )]
    };
    let artifact = KvEncArtifact::encrypt_entries(entries(), &recipients, &key_ctx).unwrap();
    let target_path = workspace.join("secrets/secret.env.kvenc");
    artifact.save(&target_path).unwrap();
    let session =
        RewrapSession::open(&workspace, Some(temp.path().to_path_buf()), &key_ctx).unwrap();
    let RewrapSessionDecision::ReviewRequired(review) = session
        .begin_rewrap(
            session.workspace_target("secret.env.kvenc").unwrap(),
            RewrapOptions::new(),
            false,
        )
        .unwrap()
    else {
        panic!("the new Bob recipient key must require review");
    };
    let replacement = KvEncArtifact::encrypt_entries(entries(), &recipients, &key_ctx).unwrap();
    replacement.save(&target_path).unwrap();

    let error = match session.resume_rewrap(review, RewrapOptions::new(), None) {
        Ok(_) => panic!("a rewritten KV target must invalidate the review"),
        Err(error) => error,
    };

    assert!(
        error.format_user_message().contains("changed since review"),
        "{}",
        error.format_user_message()
    );
    assert_eq!(
        fs::read_to_string(target_path).unwrap(),
        replacement.as_str()
    );
}

#[test]
fn reviewed_approval_advances_only_the_opaque_rewrap_review() {
    let (temp, workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&temp, ALICE, None));
    let recipients = LocalKeyStore::open(temp.path().join("keys"))
        .unwrap()
        .load_recipient_keys([member(ALICE)])
        .unwrap();
    let artifact = FileEncArtifact::encrypt_bytes(b"secret", &recipients, &key_ctx).unwrap();
    artifact
        .save(workspace.join("secrets/secret.json"))
        .unwrap();
    let session =
        RewrapSession::open(&workspace, Some(temp.path().to_path_buf()), &key_ctx).unwrap();
    let RewrapSessionDecision::ReviewRequired(mut review) = session
        .begin_rewrap(
            session.workspace_target("secret.json").unwrap(),
            RewrapOptions::new(),
            false,
        )
        .unwrap()
    else {
        panic!("the new Bob recipient key must require review");
    };
    let candidate = review.requests()[0].known_key_candidate().unwrap();
    let approval = TrustApproval::known_key(candidate, KnownKeyApprovalEvidence::none()).unwrap();

    session
        .apply_review_approval(&mut review, approval)
        .unwrap();
    let resumed = session.resume_rewrap(review, RewrapOptions::new(), None);

    assert!(
        resumed.is_ok(),
        "the reviewed approval must advance the review"
    );
}

#[test]
fn non_member_rewrap_exposes_recipient_reviews_only_after_signer_acceptance() {
    let (temp, workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB, CAROL]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).unwrap();
    let recipients = key_store
        .load_recipient_keys([member(ALICE), member(CAROL)])
        .unwrap();
    let signer_ctx = KeyContext::from_inner(setup_member_key_context(&temp, BOB, None));
    let artifact = FileEncArtifact::encrypt_bytes(b"secret", &recipients, &signer_ctx).unwrap();
    artifact
        .save(workspace.join("secrets/non-member.json"))
        .unwrap();
    fs::remove_file(workspace.join("members/active").join(format!("{BOB}.json"))).unwrap();
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&temp, ALICE, None));
    let session =
        RewrapSession::open(&workspace, Some(temp.path().to_path_buf()), &key_ctx).unwrap();

    let RewrapSessionDecision::ReviewRequired(mut signer_review) = session
        .begin_rewrap(
            session.workspace_target("non-member.json").unwrap(),
            RewrapOptions::new(),
            true,
        )
        .unwrap()
    else {
        panic!("the non-member signer must require review");
    };
    assert!(signer_review.non_member_signer().is_some());
    assert!(signer_review.requests().is_empty());
    let acceptance = signer_review.accept_non_member().unwrap();

    let RewrapSessionDecision::ReviewRequired(recipient_review) = session
        .resume_rewrap(signer_review, RewrapOptions::new(), Some(acceptance))
        .unwrap()
    else {
        panic!("recipient reviews must follow signer acceptance");
    };

    assert!(recipient_review.non_member_signer().is_none());
    assert!(!recipient_review.requests().is_empty());
}

#[cfg(unix)]
fn assert_explicit_publish_rejects_parent_swap<F>(name: &str, build_artifact: F)
where
    F: FnOnce(&RecipientKeys, &KeyContext) -> String,
{
    let (_temp, workspace, key_ctx, recipients) = setup_self();
    let artifact = build_artifact(&recipients, &key_ctx);
    let session = RewrapSession::open(&workspace, None, &key_ctx).unwrap();
    let explicit_root = tempfile::tempdir().unwrap();
    let target_dir = explicit_root.path().join("targets");
    let substitute_dir = explicit_root.path().join("substitute");
    fs::create_dir(&target_dir).unwrap();
    fs::create_dir(&substitute_dir).unwrap();
    fs::write(target_dir.join(name), &artifact).unwrap();
    fs::write(substitute_dir.join(name), &artifact).unwrap();

    let target = RewrapTarget::open(target_dir.join(name)).unwrap();
    let RewrapSessionDecision::Authorized(authorized) = session
        .begin_rewrap(target, RewrapOptions::new(), false)
        .unwrap()
    else {
        panic!("self-only explicit rewrap must be authorized");
    };
    let reviewed_dir = explicit_root.path().join("reviewed-targets");
    let swap_target = target_dir.clone();
    set_pre_publish_hook(move || {
        fs::rename(&swap_target, &reviewed_dir).unwrap();
        fs::rename(&substitute_dir, &swap_target).unwrap();
    });

    let error = authorized.publish().unwrap_err();

    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
    assert_eq!(fs::read_to_string(target_dir.join(name)).unwrap(), artifact);
    assert_eq!(
        fs::read_to_string(explicit_root.path().join("reviewed-targets").join(name)).unwrap(),
        artifact
    );
}

#[cfg(unix)]
#[test]
fn explicit_file_rewrap_rejects_parent_directory_swap_before_publish() {
    assert_explicit_publish_rejects_parent_swap("secret.json", |recipients, key_ctx| {
        FileEncArtifact::encrypt_bytes(b"secret", recipients, key_ctx)
            .unwrap()
            .as_str()
            .to_string()
    });
}

#[cfg(unix)]
#[test]
fn explicit_kv_rewrap_rejects_parent_directory_swap_before_publish() {
    assert_explicit_publish_rejects_parent_swap("secret.env.kvenc", |recipients, key_ctx| {
        KvEncArtifact::encrypt_entries(
            vec![KvInputEntry::new(
                "SECRET",
                SecretString::new("value".to_string()),
            )],
            recipients,
            key_ctx,
        )
        .unwrap()
        .as_str()
        .to_string()
    });
}

#[cfg(unix)]
#[test]
fn test_explicit_rewrap_parent_component_swap_before_publish_error() {
    let (_temp, workspace, key_ctx, recipients) = setup_self();
    let artifact = FileEncArtifact::encrypt_bytes(b"secret", &recipients, &key_ctx)
        .unwrap()
        .as_str()
        .to_string();
    let session = RewrapSession::open(&workspace, None, &key_ctx).unwrap();
    let explicit_root = tempfile::tempdir().unwrap();
    let target_dir = explicit_root.path().join("targets");
    let substitute_dir = explicit_root.path().join("substitute");
    let reviewed_dir = explicit_root.path().join("reviewed-targets");
    for directory in [&target_dir, &substitute_dir] {
        fs::create_dir(directory).unwrap();
        fs::create_dir(directory.join("nested")).unwrap();
        fs::write(directory.join("secret.json"), &artifact).unwrap();
    }
    let target = RewrapTarget::open(target_dir.join("nested/../secret.json")).unwrap();
    let RewrapSessionDecision::Authorized(authorized) = session
        .begin_rewrap(target, RewrapOptions::new(), false)
        .unwrap()
    else {
        panic!("self-only explicit file rewrap must be authorized");
    };
    let swap_target = target_dir.clone();
    set_pre_publish_hook(move || {
        fs::rename(&swap_target, &reviewed_dir).unwrap();
        fs::rename(&substitute_dir, &swap_target).unwrap();
    });

    let error = authorized.publish().unwrap_err();

    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
    assert_eq!(
        fs::read_to_string(target_dir.join("secret.json")).unwrap(),
        artifact
    );
    assert_eq!(
        fs::read_to_string(explicit_root.path().join("reviewed-targets/secret.json")).unwrap(),
        artifact
    );
}

#[test]
fn test_rewrap_rejects_recipients_from_stale_post_promotion_snapshot() {
    let (temp, _workspace, key_ctx, recipients) = setup_self();
    let verified = FileEncArtifact::encrypt_bytes(b"secret", &recipients, &key_ctx)
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap();
    let (_changed_temp, changed_workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let pre = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::from_recipient_keys(&recipients).unwrap(),
        None,
    );
    let post = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&changed_workspace).unwrap(),
        None,
    );

    let error = match post.evaluate_rewrap(
        &pre,
        verified,
        recipients,
        &key_ctx,
        RewrapOptions::new(),
        None,
    ) {
        Ok(TrustDecision::Trusted(_)) => {
            panic!("stale output recipients must not receive a capability")
        }
        Ok(TrustDecision::ReviewRequired(_)) => {
            panic!("member-set mismatch cannot be approved as trust review")
        }
        Err(error) => error,
    };

    drop(temp);
    assert_eq!(error.rule(), Some("E_TRUST_REJECTED"));
}
