// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::test_support::remove_active_member as remove_member;
use super::*;
use crate::support::fs::lock::lock_test_support::with_locked_workspace_dir;
use crate::support::fs::relative::{open_dir_nofollow, DirectoryScope, OpenDir};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Bind the workspace the way a command does, so the member store writes through
/// the descriptor rather than resolving the path a second time.
fn open_workspace(workspace_path: &Path) -> OpenDir {
    open_dir_nofollow(workspace_path, DirectoryScope::Generic).unwrap()
}

#[test]
fn test_remove_member_removes_file() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(active_dir.join("alice.json"), "{}").unwrap();

    remove_member(tmp.path(), "alice").unwrap();

    assert!(!active_dir.join("alice.json").exists());
}

#[test]
fn test_remove_member_not_found() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();

    let result = remove_member(tmp.path(), "nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_save_member_content_incoming_new() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&incoming_dir).unwrap();

    save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();

    assert!(incoming_dir.join("alice.json").exists());
    let content = fs::read_to_string(incoming_dir.join("alice.json")).unwrap();
    assert!(content.contains("\"subject_handle\": \"alice\""));
}

#[test]
fn test_save_member_content_creates_directory_if_missing() {
    let tmp = TempDir::new().unwrap();

    save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();

    let content = fs::read_to_string(tmp.path().join("members/incoming/alice.json")).unwrap();
    assert!(content.contains("\"subject_handle\": \"alice\""));
}

#[test]
fn test_save_member_content_incoming_already_exists_no_force() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(
        incoming_dir.join("alice.json"),
        build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();

    let result = save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
        false,
    );
    assert!(result.is_err());
    let content = fs::read_to_string(incoming_dir.join("alice.json")).unwrap();
    assert!(content.contains("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"));
}

#[test]
fn test_save_member_content_force_overwrite() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(
        incoming_dir.join("alice.json"),
        build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();

    save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
        true,
    )
    .unwrap();

    let content = fs::read_to_string(incoming_dir.join("alice.json")).unwrap();
    assert!(content.contains("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"));
}

#[test]
fn test_save_member_content_keeping_existing_reports_a_created_document() {
    let tmp = TempDir::new().unwrap();

    let write = save_member_content_keeping_existing(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();

    assert_eq!(write, MemberDocumentWrite::Created);
}

/// The name the write takes is settled under the same lock as the write, so a
/// document that turned up after the caller last looked at the path is reported
/// as the replacement it is rather than as a creation.
#[test]
fn test_save_member_content_keeping_existing_reports_a_document_that_appeared_under_the_lock() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    let appearing = incoming_dir.join("alice.json");
    set_post_open_save_dirs_hook({
        let appearing = appearing.clone();
        move || fs::write(&appearing, "{}").unwrap()
    });

    let write = save_member_content_keeping_existing(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        true,
    )
    .unwrap();

    assert_eq!(write, MemberDocumentWrite::Replaced);
    assert!(fs::read_to_string(&appearing)
        .unwrap()
        .contains("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"));
}

/// Without `--force` the document that is there stands, and the caller is told
/// so instead of being handed a failure.
#[test]
fn test_save_member_content_keeping_existing_keeps_the_stored_document() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(
        incoming_dir.join("alice.json"),
        build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();

    let write = save_member_content_keeping_existing(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
        false,
    )
    .unwrap();

    assert_eq!(write, MemberDocumentWrite::Kept);
    let content = fs::read_to_string(incoming_dir.join("alice.json")).unwrap();
    assert!(content.contains("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"));
}

#[cfg(unix)]
#[test]
fn test_save_member_content_rejects_symlinked_target_on_force_overwrite() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    let victim_path = tmp.path().join("victim.txt");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(&victim_path, "original").unwrap();
    symlink(&victim_path, incoming_dir.join("alice.json")).unwrap();

    let error = save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
        true,
    )
    .unwrap_err();

    assert!(error.to_string().contains("symlink"));
    assert_eq!(fs::read_to_string(&victim_path).unwrap(), "original");
}

#[cfg(unix)]
#[test]
fn test_save_member_content_rejects_symlinked_incoming_directory() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let members_dir = tmp.path().join("members");
    let outside_dir = tmp.path().join("outside");
    fs::create_dir_all(&members_dir).unwrap();
    fs::create_dir(&outside_dir).unwrap();
    symlink(&outside_dir, members_dir.join("incoming")).unwrap();

    let error = save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
        false,
    )
    .unwrap_err();

    // The refusal keeps its own kind: flattening it into a plain I/O failure
    // would hide from a caller that a name was repointed rather than a write
    // going wrong.
    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(error.to_string().contains("symlink"));
    assert!(
        !outside_dir.join("alice.json").exists(),
        "member file must not be written outside the workspace"
    );
}

#[test]
fn test_save_member_content_rejects_directory_target() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(incoming_dir.join("alice.json")).unwrap();

    let error = save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        true,
    )
    .unwrap_err();

    assert!(error.to_string().contains("directory"));
    assert!(incoming_dir.join("alice.json").is_dir());
}

#[test]
fn test_save_member_content_rejects_kid_conflict_with_active_member() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(
        active_dir.join("alice.json"),
        build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();

    let result = save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "bob",
        &build_public_key_json("bob", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    );

    assert!(result.is_err());
    assert!(!tmp.path().join("members/incoming/bob.json").exists());
}

#[test]
fn test_save_member_content_rejects_kid_conflict_with_incoming_member() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(
        incoming_dir.join("alice.json"),
        build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();

    let result = save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "bob",
        &build_public_key_json("bob", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    );

    assert!(result.is_err());
    assert!(!incoming_dir.join("bob.json").exists());
}

#[test]
fn test_save_member_content_active_error_uses_active_directory_name() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(
        active_dir.join("alice.json"),
        build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();

    let result = save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Active,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
        false,
    );
    let err = result.unwrap_err().to_string();

    assert!(err.contains("active/"));
}

/// The kid is judged against the member set the lock opened, not the one the
/// path resolves to by the time the write lands. `members/active` is repointed
/// at an empty directory while the lock is held, and the duplicate is still
/// refused, because the check reads through the descriptor the lock produced.
#[test]
fn test_save_member_content_judges_the_kid_against_the_active_directory_it_opened() {
    const KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let tmp = TempDir::new().unwrap();
    let members_dir = tmp.path().join("members");
    let active_dir = members_dir.join("active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::create_dir_all(members_dir.join("incoming")).unwrap();
    fs::write(
        active_dir.join("alice.json"),
        build_public_key_json("alice", KID),
    )
    .unwrap();

    let repointed = active_dir.clone();
    let relocated = members_dir.join("active.real");
    set_post_open_save_dirs_hook(move || {
        fs::rename(&repointed, &relocated).unwrap();
        fs::create_dir(&repointed).unwrap();
    });

    let error = save_member_content(
        &open_workspace(tmp.path()),
        MemberStatus::Incoming,
        "bob",
        &build_public_key_json("bob", KID),
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("Duplicate kid"), "{error}");
    assert!(!members_dir.join("incoming").join("bob.json").exists());
}

/// A removal and a promotion have to exclude each other, and `flock` arbitrates
/// per inode, so both must lock the same directory. The removal is run with
/// `members/` already locked on this thread: the lock registry refuses the second
/// take, which is only reached if the removal asks for that very directory.
#[test]
fn test_member_removal_takes_the_lock_on_the_members_root() {
    let tmp = TempDir::new().unwrap();
    let members_dir = tmp.path().join("members");
    let active_dir = members_dir.join("active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(active_dir.join("alice.json"), "{}").unwrap();
    let reviewed = review_active_member_document(&open_workspace(tmp.path()), "alice").unwrap();

    let error = with_locked_workspace_dir(&members_dir, |_| reviewed.remove()).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("nested directory locks are not allowed"),
        "removal did not lock members/: {error}"
    );
    assert!(active_dir.join("alice.json").exists());
}

/// The lock fixes `members/`, so `active/` below it can still be repointed
/// between the review and the unlink. The replacement holds a hard link to the
/// reviewed document, which passes the identity check on the file itself, and
/// the removal is still refused because the directory is not the reviewed one.
#[test]
fn test_member_removal_refuses_an_active_directory_repointed_since_review() {
    let tmp = TempDir::new().unwrap();
    let members_dir = tmp.path().join("members");
    let active_dir = members_dir.join("active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(active_dir.join("alice.json"), "{}").unwrap();
    let reviewed = review_active_member_document(&open_workspace(tmp.path()), "alice").unwrap();

    let relocated = members_dir.join("active.real");
    fs::rename(&active_dir, &relocated).unwrap();
    fs::create_dir(&active_dir).unwrap();
    fs::hard_link(relocated.join("alice.json"), active_dir.join("alice.json")).unwrap();

    let error = reviewed.remove().unwrap_err();

    assert!(
        error.to_string().contains("changed since review"),
        "unexpected error: {error}"
    );
    assert!(relocated.join("alice.json").exists());
    assert!(active_dir.join("alice.json").exists());
}

fn replace_active_member_document(path: &Path, content: &str) {
    let replacement = path.with_extension("replacement");
    fs::write(&replacement, content).unwrap();
    fs::rename(replacement, path).unwrap();
}

fn find_quarantined_member_document(active_dir: &Path) -> std::path::PathBuf {
    let mut quarantined = fs::read_dir(active_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".alice.json.tmp."))
        })
        .collect::<Vec<_>>();
    assert_eq!(quarantined.len(), 1, "{quarantined:?}");
    quarantined.remove(0)
}

/// A writer that replaces the reviewed name after its final comparison must
/// not have its new member document deleted by the removal.
#[test]
fn test_member_removal_restores_a_document_replaced_after_comparison() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    let member_path = active_dir.join("alice.json");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(&member_path, "reviewed").unwrap();
    let reviewed = review_active_member_document(&open_workspace(tmp.path()), "alice").unwrap();
    let replaced = member_path.clone();
    set_member_pre_quarantine_hook(move || {
        replace_active_member_document(&replaced, "replacement")
    });

    let error = reviewed.remove().unwrap_err();

    assert!(
        error.to_string().contains("must be reviewed again"),
        "{error}"
    );
    assert_eq!(fs::read_to_string(&member_path).unwrap(), "replacement");
    assert_eq!(fs::read_dir(&active_dir).unwrap().count(), 1);
}

/// If another writer takes the original name before restoration, both its
/// document and the unreviewed quarantined document remain recoverable.
#[test]
fn test_member_removal_keeps_both_documents_when_restore_name_is_retaken() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    let member_path = active_dir.join("alice.json");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(&member_path, "reviewed").unwrap();
    let reviewed = review_active_member_document(&open_workspace(tmp.path()), "alice").unwrap();
    let replaced = member_path.clone();
    set_member_pre_quarantine_hook(move || {
        replace_active_member_document(&replaced, "first-arrival")
    });
    let retaken = member_path.clone();
    set_member_post_quarantine_hook(move || fs::write(&retaken, "second-arrival").unwrap());

    let error = reviewed.remove().unwrap_err();

    assert!(error.to_string().contains("was not deleted"), "{error}");
    assert_eq!(fs::read_to_string(&member_path).unwrap(), "second-arrival");
    let quarantined = find_quarantined_member_document(&active_dir);
    assert_eq!(fs::read_to_string(quarantined).unwrap(), "first-arrival");
}

/// Once the reviewed document is quarantined, a new arrival at its former
/// name is outside the deletion target and must remain untouched.
#[test]
fn test_member_removal_preserves_a_new_arrival_after_quarantine() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    let member_path = active_dir.join("alice.json");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(&member_path, "reviewed").unwrap();
    let reviewed = review_active_member_document(&open_workspace(tmp.path()), "alice").unwrap();
    let arrived = member_path.clone();
    set_member_post_quarantine_hook(move || fs::write(&arrived, "new-arrival").unwrap());

    reviewed.remove().unwrap();

    assert_eq!(fs::read_to_string(&member_path).unwrap(), "new-arrival");
    assert_eq!(fs::read_dir(&active_dir).unwrap().count(), 1);
}

/// The quarantined inode is checked by content as well as identity, so a writer
/// retaining an open descriptor cannot turn it into an unreviewed deletion.
#[test]
fn test_member_removal_restores_content_changed_after_quarantine() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    let member_path = active_dir.join("alice.json");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(&member_path, "reviewed").unwrap();
    let reviewed = review_active_member_document(&open_workspace(tmp.path()), "alice").unwrap();
    let quarantine_dir = active_dir.clone();
    set_member_post_quarantine_hook(move || {
        let quarantined = find_quarantined_member_document(&quarantine_dir);
        fs::write(quarantined, "changed-after-quarantine").unwrap();
    });

    let error = reviewed.remove().unwrap_err();

    assert!(
        error.to_string().contains("must be reviewed again"),
        "{error}"
    );
    assert_eq!(
        fs::read_to_string(&member_path).unwrap(),
        "changed-after-quarantine"
    );
    assert_eq!(fs::read_dir(&active_dir).unwrap().count(), 1);
}

/// The document lands below the workspace descriptor the caller selected. The
/// workspace is moved aside and a decoy is left at the path it was opened
/// through, and the write still reaches the directory that was opened.
#[test]
fn test_save_member_content_writes_under_the_workspace_descriptor_it_was_given() {
    let tmp = TempDir::new().unwrap();
    let workspace_path = tmp.path().join("workspace");
    fs::create_dir(&workspace_path).unwrap();
    let workspace = open_workspace(&workspace_path);

    let relocated = tmp.path().join("relocated");
    fs::rename(&workspace_path, &relocated).unwrap();
    fs::create_dir(&workspace_path).unwrap();

    save_member_content(
        &workspace,
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();

    assert!(relocated.join("members/incoming/alice.json").exists());
    assert!(
        !workspace_path.join("members").exists(),
        "the write followed the path instead of the descriptor"
    );
}

fn build_public_key_json(member_handle: &str, kid: &str) -> String {
    format!(
        r#"{{
  "protected": {{
    "format": "kapsaro:format:public-key@1",
    "subject_handle": "{member_handle}",
    "kid": "{kid}",
  "keys": {{
    "kem": {{"kty":"OKP","crv":"X25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
    "sig": {{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
  }},
  "attestation": {{
    "method": "ssh-sign",
    "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
  }},
    "created_at": "2026-01-01T00:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }},
  "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}}"#
    )
}
