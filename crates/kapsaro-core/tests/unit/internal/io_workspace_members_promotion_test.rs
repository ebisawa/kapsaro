// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for io/workspace/members/promotion.
//! Covers source-directory symlink rejection during snapshotted promotion.

use super::{promote_snapshotted_incoming_members, IncomingMemberPromotionSnapshot};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn snapshot_for(
    workspace: &Path,
    member_handle: &str,
    content: &str,
) -> IncomingMemberPromotionSnapshot {
    IncomingMemberPromotionSnapshot {
        member_handle: member_handle.to_string(),
        kid: "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string(),
        source_path: workspace
            .join("members")
            .join("incoming")
            .join(format!("{member_handle}.json")),
        source_content: content.to_string(),
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
    let promoted = promote_snapshotted_incoming_members(workspace, &[snapshot]).unwrap();

    assert_eq!(promoted, vec!["alice".to_string()]);
    assert!(workspace
        .join("members")
        .join("active")
        .join("alice.json")
        .exists());
    assert!(!incoming_dir.join("alice.json").exists());
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
    let result = promote_snapshotted_incoming_members(workspace, &[snapshot]);

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

#[cfg(unix)]
#[test]
fn test_promotion_does_not_follow_incoming_path_after_directory_fd_is_opened() {
    use crate::support::fs::lock::with_locked_dir;
    use crate::support::fs::relative::{
        ensure_text_file_matches_snapshot_with_limit_at, remove_file_at, save_text_at,
    };
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

    with_locked_dir(&members_dir, |members| {
        let opened_incoming = members.open_child_dir("incoming")?;
        let opened_active = members.open_child_dir("active")?;
        fs::rename(&incoming_dir, members_dir.join("incoming.real")).unwrap();
        symlink(&outside_dir, &incoming_dir).unwrap();

        ensure_text_file_matches_snapshot_with_limit_at(
            &opened_incoming,
            "alice.json",
            Some("{}"),
            "Incoming member 'alice'",
            64,
        )?;
        save_text_at(&opened_active, "alice.json", "{}")?;
        remove_file_at(&opened_incoming, "alice.json")?;
        Ok(())
    })
    .unwrap();

    assert_eq!(
        fs::read_to_string(outside_dir.join("alice.json")).unwrap(),
        "outside"
    );
    assert!(active_dir.join("alice.json").exists());
}

#[cfg(unix)]
#[test]
fn test_promotion_uniqueness_uses_opened_active_dir_after_path_swap() {
    use crate::support::fs::lock::with_locked_dir;
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
        source_path: incoming_dir.join(format!("{BOB_MEMBER_HANDLE}.json")),
        source_content: "{}".to_string(),
    };

    with_locked_dir(&members_dir, |members| {
        let opened_incoming = members.open_child_dir("incoming")?;
        let opened_active = members.open_child_dir("active")?;
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
