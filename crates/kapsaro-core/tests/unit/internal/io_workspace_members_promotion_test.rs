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
