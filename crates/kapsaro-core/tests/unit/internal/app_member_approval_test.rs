// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use crate::app::member::approval::{
    evaluate_members_for_approval, save_member_approvals, MemberApprovalResult,
};
use crate::app_test_utils::{
    build_test_command_options, build_test_execution_context, load_test_trust_store,
};
use crate::feature::key::generate::{generate_key, KeyGenerationOptions};
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use crate::io::ssh::backend::SignatureBackend;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::protocol::fingerprint::build_sha256_fingerprint;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use crate::model::ssh::SshDeterminismStatus;
use crate::support::time::format_timestamp_rfc3339;
use crate::test_utils::member_handle;
use crate::test_utils::setup_test_workspace_from_fixtures;
#[cfg(feature = "online")]
use crate::{
    io::trust::paths::get_trust_store_file_path, support::warning::LocalStateWarningGuard,
};
use crate::{
    io::verify_online::{VerificationResult, VerifiedGithubIdentity},
    io::workspace::members::load_active_member_files,
    model::public_key::{BindingClaims, GithubAccount, PublicKey},
};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";

fn find_kid(active_members: &[PublicKey], member_handle: &str) -> String {
    active_members
        .iter()
        .find(|pk| pk.protected.subject_handle == member_handle)
        .map(|pk| pk.protected.kid.clone())
        .unwrap()
}

fn find_member(active_members: &[PublicKey], member_handle: &str) -> PublicKey {
    active_members
        .iter()
        .find(|pk| pk.protected.subject_handle == member_handle)
        .cloned()
        .unwrap()
}

fn build_verified_ssh_binding(home: &Path) -> SshBindingContext {
    let ssh_key_path = home.join(".ssh").join("test_ed25519");
    let ssh_public_key = fs::read_to_string(home.join(".ssh").join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let fingerprint = build_sha256_fingerprint(&ssh_public_key).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(ssh_key_path),
    ));
    SshBindingContext {
        public_key: ssh_public_key,
        fingerprint,
        backend,
        determinism: SshDeterminismStatus::Verified,
    }
}

fn generate_github_bound_member(home: &Path) -> PublicKey {
    let now = time::OffsetDateTime::now_utc();
    generate_key(KeyGenerationOptions {
        member_handle: BOB_MEMBER_HANDLE.to_string(),
        created_at: format_timestamp_rfc3339(now).unwrap(),
        expires_at: format_timestamp_rfc3339(now + time::Duration::days(365)).unwrap(),
        github_account: Some(GithubAccount {
            id: 42,
            login: "stored-login".to_string(),
        }),
        ssh_binding: build_verified_ssh_binding(home),
    })
    .unwrap()
    .public_key
}

/// One manually reviewed approval for Bob, as the review step would leave it.
fn build_manual_approval(kid: &str, verified: bool, attestor_pub: &str) -> MemberApprovalResult {
    MemberApprovalResult {
        member_handle: BOB_MEMBER_HANDLE.to_string(),
        kid: kid.to_string(),
        verified,
        approved: true,
        review_required: true,
        already_known: false,
        message: "manual review".to_string(),
        fingerprint: None,
        github_id: None,
        github_login: None,
        github_binding_configured: false,
        attestor_pub: Some(attestor_pub.to_string()),
        verified_github: None,
    }
}

#[test]
fn test_approval_online_verifier_runs_once_per_bound_candidate_only() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let targets = vec![BOB_MEMBER_HANDLE.to_string()];
    let owner = member_handle(ALICE_MEMBER_HANDLE);
    let call_count = std::cell::Cell::new(0);

    super::verify_approval_targets_with_verifier(&active_members, &targets, &owner, |_| {
        call_count.set(call_count.get() + 1);
        unreachable!("an unbound candidate must not invoke online verification")
    })
    .unwrap();
    assert_eq!(call_count.get(), 0);

    let mut bound_members = active_members;
    let bob = bound_members
        .iter_mut()
        .find(|member| member.protected.subject_handle == BOB_MEMBER_HANDLE)
        .unwrap();
    bob.protected.binding_claims = Some(BindingClaims {
        github_account: Some(GithubAccount {
            id: 42,
            login: "stored-login".to_string(),
        }),
    });
    let results =
        super::verify_approval_targets_with_verifier(&bound_members, &targets, &owner, |_| {
            call_count.set(call_count.get() + 1);
            Ok(VerificationResult::failed(
                BOB_MEMBER_HANDLE,
                "injected online result".to_string(),
                None,
                true,
            ))
        })
        .unwrap();

    assert_eq!(call_count.get(), 1);
    assert_eq!(results.len(), 1);
}

#[test]
fn test_save_member_approvals_persists_only_manually_approved_candidates() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob_kid = find_kid(&active_members, BOB_MEMBER_HANDLE);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    let evaluation = crate::app::member::approval::MemberApprovalEvaluation::for_test(
        vec![build_manual_approval(
            &bob_kid,
            false,
            &find_member(&active_members, BOB_MEMBER_HANDLE)
                .protected
                .attestation
                .pub_,
        )],
        &active_members,
    )
    .unwrap();
    save_member_approvals(&options, &evaluation, &execution).unwrap();

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    assert!(loaded
        .protected
        .known_keys
        .iter()
        .any(|entry| entry.subject_handle == BOB_MEMBER_HANDLE && entry.kid == bob_kid));
}

#[test]
fn test_save_member_approvals_rejects_expired_signing_key() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob_kid = find_kid(&active_members, BOB_MEMBER_HANDLE);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    crate::test_utils::update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    let evaluation = crate::app::member::approval::MemberApprovalEvaluation::for_test(
        vec![build_manual_approval(
            &bob_kid,
            false,
            &find_member(&active_members, BOB_MEMBER_HANDLE)
                .protected
                .attestation
                .pub_,
        )],
        &active_members,
    )
    .unwrap();
    let result = save_member_approvals(&options, &evaluation, &execution);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
    assert!(load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .is_none());
}

#[test]
fn test_member_verify_approve_rejects_an_expired_target_key() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    crate::test_utils::update_active_private_key_expires_at(
        temp_dir.path(),
        BOB_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    crate::test_utils::save_active_public_key_to_workspace(
        temp_dir.path(),
        &workspace_dir,
        BOB_MEMBER_HANDLE,
    )
    .unwrap();
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let error = super::evaluate_candidate_with_snapshot(
        &crate::io::verify_online::VerificationResult::not_configured(
            BOB_MEMBER_HANDLE,
            "manual review",
            None,
            false,
        ),
        &active_members,
        &[],
    )
    .unwrap_err();

    assert_eq!(error.rule(), Some("E_KEY_EXPIRED"));
    assert!(error.to_string().contains("expired"));
}

#[test]
fn test_save_member_approvals_uses_evaluated_snapshot_without_rereading_workspace() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_HANDLE);
    let original_attestor_pub = bob.protected.attestation.pub_.clone();
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));
    let bob_file = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    let mut tampered: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bob_file).unwrap()).unwrap();
    tampered["protected"]["attestation"]["pub"] =
        serde_json::Value::String("ssh-ed25519 AAAA changed".to_string());
    fs::write(&bob_file, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

    let evaluation = crate::app::member::approval::MemberApprovalEvaluation::for_test(
        vec![build_manual_approval(
            &bob.protected.kid,
            true,
            &original_attestor_pub,
        )],
        &active_members,
    )
    .unwrap();
    save_member_approvals(&options, &evaluation, &execution).unwrap();

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    let saved = loaded
        .protected
        .known_keys
        .iter()
        .find(|entry| entry.subject_handle == BOB_MEMBER_HANDLE)
        .unwrap();
    assert_eq!(
        saved.evidence.as_ref().unwrap().ssh_attestor_pub.as_deref(),
        Some(original_attestor_pub.as_str())
    );
}

#[test]
fn test_save_member_approvals_persists_verified_github_login_from_review() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_HANDLE);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    let evaluation = crate::app::member::approval::MemberApprovalEvaluation::for_test(
        vec![MemberApprovalResult {
            member_handle: BOB_MEMBER_HANDLE.to_string(),
            kid: bob.protected.kid.clone(),
            verified: true,
            approved: true,
            review_required: true,
            already_known: false,
            message: "verified".to_string(),
            fingerprint: Some("SHA256:fp".to_string()),
            github_id: Some(42),
            github_login: Some("current-login".to_string()),
            github_binding_configured: true,
            attestor_pub: Some(bob.protected.attestation.pub_.clone()),
            verified_github: Some(VerifiedGithubIdentity::new(
                42,
                "current-login".to_string(),
                "SHA256:fp".to_string(),
                100,
            )),
        }],
        &active_members,
    )
    .unwrap();
    save_member_approvals(&options, &evaluation, &execution).unwrap();

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    let saved = loaded
        .protected
        .known_keys
        .iter()
        .find(|entry| entry.subject_handle == BOB_MEMBER_HANDLE)
        .unwrap();
    let github = saved
        .evidence
        .as_ref()
        .and_then(|evidence| evidence.github_account.as_ref())
        .unwrap();
    assert_eq!(github.id, 42);
    assert_eq!(github.login.as_deref(), Some("current-login"));
}

#[test]
fn test_member_approval_persists_opaque_evidence_from_the_single_verification_result() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let bob = generate_github_bound_member(temp_dir.path());
    let bob_path = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{BOB_MEMBER_HANDLE}.json"));
    fs::write(&bob_path, serde_json::to_vec_pretty(&bob).unwrap()).unwrap();
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let fingerprint = build_sha256_fingerprint(&bob.protected.attestation.pub_).unwrap();
    let verification = VerificationResult::verified(
        BOB_MEMBER_HANDLE,
        "verified once".to_string(),
        VerifiedGithubIdentity::new(42, "current-login".to_string(), fingerprint.clone(), 100),
    );

    let (mut result, approval) =
        super::evaluate_candidate_with_snapshot(&verification, &active_members, &[]).unwrap();
    let verified_github = result.verified_github.as_ref().unwrap();
    assert_eq!(verified_github.id, 42);
    assert_eq!(verified_github.login, "current-login");
    assert_eq!(verified_github.fingerprint, fingerprint);
    assert_eq!(verified_github.matched_key_id, 100);

    result.approved = true;
    result.github_id = Some(999);
    result.github_login = Some("display-only-change".to_string());
    let approval = approval.expect("verified candidate must carry opaque approval evidence");
    let mut approvals = std::collections::BTreeMap::new();
    approvals.insert(approval.kid().clone(), approval);
    let evaluation = super::MemberApprovalEvaluation {
        results: vec![result],
        approvals,
    };
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    save_member_approvals(&options, &evaluation, &execution).unwrap();

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    let saved = loaded
        .protected
        .known_keys
        .iter()
        .find(|entry| entry.subject_handle == BOB_MEMBER_HANDLE)
        .unwrap();
    let evidence = saved.evidence.as_ref().unwrap();
    let github = evidence.github_account.as_ref().unwrap();
    assert_eq!(github.id, 42);
    assert_eq!(github.login.as_deref(), Some("current-login"));
    assert_eq!(
        evidence.ssh_attestor_pub.as_deref(),
        Some(bob.protected.attestation.pub_.as_str())
    );
}

#[cfg(unix)]
#[cfg(feature = "online")]
#[test]
fn test_evaluate_members_for_approval_warns_about_insecure_trust_store() {
    use std::os::unix::fs::PermissionsExt;

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_HANDLE);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    let approval = crate::app::member::approval::MemberApprovalEvaluation::for_test(
        vec![build_manual_approval(
            &bob.protected.kid,
            true,
            &bob.protected.attestation.pub_,
        )],
        &active_members,
    )
    .unwrap();
    save_member_approvals(&options, &approval, &execution).unwrap();

    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let warning_guard = LocalStateWarningGuard::new();
    evaluate_members_for_approval(&execution, &[BOB_MEMBER_HANDLE.to_string()]).unwrap();
    let warnings = warning_guard.take_reasons();

    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("Insecure permissions 0644"),
        "{warnings:?}"
    );
    assert!(warnings[0].contains("chmod 0600"), "{warnings:?}");
}

/// The evaluation reads the trust store of the home the command resolved,
/// even when another directory takes that path before the review starts.
#[cfg(unix)]
#[cfg(feature = "online")]
#[test]
fn test_evaluate_members_for_approval_reads_trust_store_of_fixed_home() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_HANDLE);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));
    let approval = crate::app::member::approval::MemberApprovalEvaluation::for_test(
        vec![build_manual_approval(
            &bob.protected.kid,
            true,
            &bob.protected.attestation.pub_,
        )],
        &active_members,
    )
    .unwrap();
    save_member_approvals(&options, &approval, &execution).unwrap();

    // A second fixture home holds the same workspace and keystore, but no
    // trust store: reading it would report Bob as an unreviewed candidate.
    let (replacement, _) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let opened_home = temp_dir.path().with_extension("opened");
    fs::rename(temp_dir.path(), &opened_home).unwrap();
    fs::rename(replacement.path(), temp_dir.path()).unwrap();

    let evaluation =
        evaluate_members_for_approval(&execution, &[BOB_MEMBER_HANDLE.to_string()]).unwrap();

    assert_eq!(evaluation.results.len(), 1);
    assert!(
        evaluation.results[0].already_known,
        "{:?}",
        evaluation.results[0]
    );

    drop(execution);
    fs::rename(temp_dir.path(), replacement.path()).unwrap();
    fs::rename(&opened_home, temp_dir.path()).unwrap();
}

/// The evaluation reads the member set of the workspace the command resolved,
/// even when another tree takes that path before the review starts.
#[cfg(unix)]
#[cfg(feature = "online")]
#[test]
fn test_evaluate_members_for_approval_reads_members_of_fixed_workspace() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    // A second workspace holds Alice alone, so a read addressed by path would
    // report Bob as missing from active/.
    let (_replacement, replacement_workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let opened_workspace = workspace_dir.with_extension("opened");
    fs::rename(&workspace_dir, &opened_workspace).unwrap();
    fs::rename(&replacement_workspace, &workspace_dir).unwrap();

    let evaluation =
        evaluate_members_for_approval(&execution, &[BOB_MEMBER_HANDLE.to_string()]).unwrap();

    assert_eq!(evaluation.results.len(), 1);
    assert_eq!(evaluation.results[0].member_handle, BOB_MEMBER_HANDLE);
}

#[test]
fn test_evaluate_members_for_approval_rejects_incoming_member() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    fs::rename(&bob_active, &bob_incoming).unwrap();
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    let result = evaluate_members_for_approval(&execution, &[BOB_MEMBER_HANDLE.to_string()]);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not found in active/"));
}

#[cfg(feature = "online")]
#[test]
fn test_evaluate_members_for_approval_excludes_self_from_default_targets() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    let evaluation = evaluate_members_for_approval(&execution, &[]).unwrap();

    assert_eq!(evaluation.results.len(), 1);
    assert_eq!(evaluation.results[0].member_handle, BOB_MEMBER_HANDLE);
}
