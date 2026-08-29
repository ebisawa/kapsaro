// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for io/workspace/members/promotion.
//! Covers source-directory symlink rejection during snapshotted promotion.

use super::{
    capture_promotion_destination_at, promote_snapshotted_incoming_members_at,
    IncomingMemberPromotionSnapshot, PromotionDestinationState,
};
use crate::support::fs::relative::{open_dir_nofollow, DirectoryScope, OpenDir};
use crate::support::limits::MAX_MEMBER_HANDLE_LENGTH;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Bind the workspace the way a command does, so the promotion acts through
/// the descriptor rather than resolving the path a second time.
fn open_workspace(workspace: &Path) -> OpenDir {
    open_dir_nofollow(workspace, DirectoryScope::Generic).unwrap()
}

fn snapshot_for(
    workspace: &Path,
    member_handle: &str,
    content: &str,
) -> IncomingMemberPromotionSnapshot {
    IncomingMemberPromotionSnapshot {
        member_handle: member_handle.to_string(),
        kid: "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string(),
        source_content: content.to_string(),
        destination: capture_promotion_destination_at(&open_workspace(workspace), member_handle)
            .unwrap(),
    }
}

#[test]
fn test_promotion_moves_incoming_member_to_active() {
    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path();
    let incoming_dir = workspace.join("members").join("incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(incoming_dir.join("alice.json"), "{}").unwrap();

    let snapshot = snapshot_for(workspace, "alice", "{}");
    let promoted =
        promote_snapshotted_incoming_members_at(&open_workspace(workspace), &[snapshot]).unwrap();

    assert_eq!(promoted, vec!["alice".to_string()]);
    assert!(workspace
        .join("members")
        .join("active")
        .join("alice.json")
        .exists());
    assert!(!incoming_dir.join("alice.json").exists());
}

/// Build a member handle of exactly `length` bytes that still reads as one.
fn build_member_handle(length: usize) -> String {
    const DOMAIN: &str = "@example.com";
    format!("{}{DOMAIN}", "a".repeat(length - DOMAIN.len()))
}

/// A handle the workspace accepts has to be promotable.
///
/// The promotion stages its document beside the target, and staging is what the
/// atomic write already does. Doing it a second time in the caller consumed the
/// name budget twice, so the longest handles registration accepts were refused
/// at their first promotion.
#[test]
fn test_promotion_moves_a_member_whose_handle_fills_the_registered_maximum() {
    let member_handle = build_member_handle(MAX_MEMBER_HANDLE_LENGTH);
    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path();
    let incoming_dir = workspace.join("members").join("incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    let file_name = format!("{member_handle}.json");
    fs::write(incoming_dir.join(&file_name), "{}").unwrap();

    let snapshot = snapshot_for(workspace, &member_handle, "{}");
    let promoted = promote_snapshotted_incoming_members_at(&open_workspace(workspace), &[snapshot])
        .unwrap_or_else(|error| panic!("the longest registrable handle must promote: {error}"));

    assert_eq!(promoted, vec![member_handle]);
    assert_eq!(
        fs::read_to_string(workspace.join("members").join("active").join(&file_name)).unwrap(),
        "{}"
    );
    assert!(!incoming_dir.join(&file_name).exists());
}

#[cfg(unix)]
#[test]
fn test_promotion_rejects_symlinked_incoming_directory() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path();
    fs::create_dir_all(workspace.join("members").join("active")).unwrap();

    // A directory outside the workspace that the attacker points `incoming/` at.
    let outside_dir = temp_dir.path().join("outside");
    fs::create_dir_all(&outside_dir).unwrap();
    let victim = outside_dir.join("alice.json");
    fs::write(&victim, "{}").unwrap();

    // Swap `members/incoming` for a symlink to the outside directory.
    symlink(&outside_dir, workspace.join("members").join("incoming")).unwrap();

    let snapshot = snapshot_for(workspace, "alice", "{}");
    let result = promote_snapshotted_incoming_members_at(&open_workspace(workspace), &[snapshot]);

    assert!(
        result.is_err(),
        "expected symlinked incoming/ to be rejected"
    );
    // The file behind the symlink must not be read into active nor deleted.
    assert!(victim.exists(), "victim file outside workspace was removed");
    assert!(!workspace
        .join("members")
        .join("active")
        .join("alice.json")
        .exists());
}

/// A promotion reads and clears the incoming directory it opened, not the one
/// the path names by the time it writes. The path is repointed at an outside
/// directory while the lock is held, and the promotion still takes the document
/// it opened and leaves the outside one untouched.
#[cfg(unix)]
#[test]
fn test_promotion_stays_bound_to_the_opened_incoming_directory() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path();
    let members_dir = workspace.join("members");
    let incoming_dir = members_dir.join("incoming");
    let active_dir = members_dir.join("active");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(incoming_dir.join("alice.json"), "{}").unwrap();

    let outside_dir = temp_dir.path().join("outside");
    fs::create_dir(&outside_dir).unwrap();
    fs::write(outside_dir.join("alice.json"), "outside").unwrap();

    let snapshot = snapshot_for(workspace, "alice", "{}");
    let moved_incoming = members_dir.join("incoming.real");
    let repointed = incoming_dir.clone();
    let target = outside_dir.clone();
    let relocated = moved_incoming.clone();
    super::set_post_open_member_dirs_hook(move || {
        fs::rename(&repointed, &relocated).unwrap();
        symlink(&target, &repointed).unwrap();
    });

    let promoted =
        promote_snapshotted_incoming_members_at(&open_workspace(workspace), &[snapshot]).unwrap();

    assert_eq!(promoted, vec!["alice".to_string()]);
    assert_eq!(
        fs::read_to_string(outside_dir.join("alice.json")).unwrap(),
        "outside"
    );
    assert_eq!(
        fs::read_to_string(active_dir.join("alice.json")).unwrap(),
        "{}"
    );
    assert!(!moved_incoming.join("alice.json").exists());
}

#[cfg(unix)]
#[test]
fn test_promotion_uniqueness_uses_opened_active_dir_after_path_swap() {
    use crate::support::fs::lock::lock_test_support::with_locked_workspace_dir;
    use crate::test_utils::{
        setup_test_workspace_from_fixtures, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
    };

    let (_home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let members_dir = workspace.join("members");
    let incoming_dir = members_dir.join("incoming");
    let active_dir = members_dir.join("active");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(incoming_dir.join(format!("{BOB_MEMBER_HANDLE}.json")), "{}").unwrap();

    let alice = fs::read_to_string(active_dir.join(format!("{ALICE_MEMBER_HANDLE}.json"))).unwrap();
    let alice: serde_json::Value = serde_json::from_str(&alice).unwrap();
    let duplicate_kid = alice["protected"]["kid"].as_str().unwrap().to_string();
    let snapshot = IncomingMemberPromotionSnapshot {
        member_handle: BOB_MEMBER_HANDLE.to_string(),
        kid: duplicate_kid,
        source_content: "{}".to_string(),
        destination: PromotionDestinationState::Missing,
    };

    with_locked_workspace_dir(&members_dir, |members| {
        let opened_incoming = super::open_status_dir_at(members, super::MemberStatus::Incoming)?;
        let opened_active = super::open_status_dir_at(members, super::MemberStatus::Active)?;
        fs::rename(&active_dir, members_dir.join("active.real")).unwrap();
        fs::create_dir(&active_dir).unwrap();

        let error = super::ensure_snapshotted_promotion_kids_are_unique(
            &opened_active,
            &opened_incoming,
            &[snapshot],
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("Duplicate kid"),
            "unexpected error: {error}"
        );
        Ok(())
    })
    .unwrap();
}

/// A promotion approved against one active document must not erase another that
/// replaced it afterwards. The snapshot records what was reviewed, so the write
/// is refused rather than silently overwriting the newer document.
#[test]
fn test_promotion_refuses_an_active_document_changed_since_review() {
    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path();
    let incoming_dir = workspace.join("members").join("incoming");
    let active_dir = workspace.join("members").join("active");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(incoming_dir.join("alice.json"), "{}").unwrap();
    fs::write(active_dir.join("alice.json"), "{\"reviewed\":true}").unwrap();

    let snapshot = snapshot_for(workspace, "alice", "{}");
    fs::write(active_dir.join("alice.json"), "{\"rotated\":true}").unwrap();

    let error = promote_snapshotted_incoming_members_at(&open_workspace(workspace), &[snapshot])
        .unwrap_err();

    assert!(
        error.to_string().contains("changed since review"),
        "unexpected error: {error}"
    );
    assert_eq!(
        fs::read_to_string(active_dir.join("alice.json")).unwrap(),
        "{\"rotated\":true}"
    );
    assert!(incoming_dir.join("alice.json").exists());
}

/// A member new to active/ must not take over a name something else created
/// between the review and the write.
#[test]
fn test_promotion_refuses_a_new_active_document_that_appeared_after_review() {
    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path();
    let incoming_dir = workspace.join("members").join("incoming");
    let active_dir = workspace.join("members").join("active");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(incoming_dir.join("alice.json"), "{}").unwrap();

    let snapshot = snapshot_for(workspace, "alice", "{}");
    fs::write(active_dir.join("alice.json"), "{\"appeared\":true}").unwrap();

    let error = promote_snapshotted_incoming_members_at(&open_workspace(workspace), &[snapshot])
        .unwrap_err();

    assert!(
        error.to_string().contains("changed since review"),
        "unexpected error: {error}"
    );
    assert_eq!(
        fs::read_to_string(active_dir.join("alice.json")).unwrap(),
        "{\"appeared\":true}"
    );
}
