// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::fs;
use tempfile::TempDir;

fn setup_workspace_with_incoming(member_ids: &[&str]) -> TempDir {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&active_dir).unwrap();
    fs::create_dir_all(&incoming_dir).unwrap();
    for (index, id) in member_ids.iter().enumerate() {
        let path = incoming_dir.join(format!("{}.json", id));
        fs::write(&path, build_public_key_json(id, &test_kid(index))).unwrap();
    }
    tmp
}

#[test]
fn test_promote_specified_selects_only_specified() {
    let tmp = setup_workspace_with_incoming(&["alice", "bob", "carol"]);
    let promoted =
        promote_specified_incoming_members(tmp.path(), &["alice".to_string(), "carol".to_string()])
            .unwrap();
    assert_eq!(promoted, vec!["alice".to_string(), "carol".to_string()]);
    assert!(tmp.path().join("members/active/alice.json").exists());
    assert!(tmp.path().join("members/active/carol.json").exists());
    assert!(tmp.path().join("members/incoming/bob.json").exists());
    assert!(!tmp.path().join("members/active/bob.json").exists());
}

#[test]
fn test_promote_specified_replaces_existing_active_member_with_same_member_id() {
    let tmp = setup_workspace_with_incoming(&["alice"]);
    fs::write(
        tmp.path().join("members/active/alice.json"),
        build_public_key_json("alice", &test_kid(9)),
    )
    .unwrap();

    let promoted = promote_specified_incoming_members(tmp.path(), &["alice".to_string()]).unwrap();

    assert_eq!(promoted, vec!["alice".to_string()]);
    assert!(!tmp.path().join("members/incoming/alice.json").exists());
    let active = fs::read_to_string(tmp.path().join("members/active/alice.json")).unwrap();
    assert!(active.contains(&test_kid(0)));
    assert!(!active.contains(&test_kid(9)));
}

#[test]
fn test_promote_specified_not_found_error() {
    let tmp = setup_workspace_with_incoming(&["alice"]);
    let result = promote_specified_incoming_members(tmp.path(), &["nonexistent".to_string()]);
    assert!(result.is_err());
}

#[test]
fn test_promote_specified_empty_list() {
    let tmp = setup_workspace_with_incoming(&["alice"]);
    let promoted = promote_specified_incoming_members(tmp.path(), &[]).unwrap();
    assert!(promoted.is_empty());
    assert!(tmp.path().join("members/incoming/alice.json").exists());
}

#[test]
fn test_promote_specified_rejects_kid_conflict_with_active_member() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&active_dir).unwrap();
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(
        active_dir.join("alice.json"),
        build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();
    fs::write(
        incoming_dir.join("bob.json"),
        build_public_key_json("bob", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();

    let result = promote_specified_incoming_members(tmp.path(), &["bob".to_string()]);
    let error = result.unwrap_err().to_string();

    assert!(error.contains("kid"));
    assert!(tmp.path().join("members/incoming/bob.json").exists());
    assert!(!tmp.path().join("members/active/bob.json").exists());
}

#[test]
fn test_promote_specified_rejects_duplicate_kids_within_batch() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&active_dir).unwrap();
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(
        incoming_dir.join("alice.json"),
        build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();
    fs::write(
        incoming_dir.join("bob.json"),
        build_public_key_json("bob", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();

    let result =
        promote_specified_incoming_members(tmp.path(), &["alice".to_string(), "bob".to_string()]);
    let error = result.unwrap_err().to_string();

    assert!(error.contains("kid"));
    assert!(tmp.path().join("members/incoming/alice.json").exists());
    assert!(tmp.path().join("members/incoming/bob.json").exists());
}

#[test]
fn test_promote_specified_rejects_kid_conflict_with_incoming_member_during_rotation() {
    // alice has a staged new key in incoming with KID_1
    // bob also has KID_1 in incoming — this conflict must be detected even though
    // incoming members were not checked by the old implementation
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&active_dir).unwrap();
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(
        active_dir.join("alice.json"),
        build_public_key_json("alice", &test_kid(0)),
    )
    .unwrap();
    fs::write(
        incoming_dir.join("alice.json"),
        build_public_key_json("alice", &test_kid(1)),
    )
    .unwrap();
    fs::write(
        incoming_dir.join("bob.json"),
        build_public_key_json("bob", &test_kid(1)),
    )
    .unwrap();

    let result = promote_specified_incoming_members(tmp.path(), &["bob".to_string()]);
    let error = result.unwrap_err().to_string();

    assert!(error.contains("kid"));
    assert!(tmp.path().join("members/incoming/bob.json").exists());
    assert!(!tmp.path().join("members/active/bob.json").exists());
}

#[test]
fn test_delete_member_removes_file() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(active_dir.join("alice.json"), "{}").unwrap();

    delete_member(tmp.path(), "alice").unwrap();

    assert!(!active_dir.join("alice.json").exists());
}

#[test]
fn test_delete_member_not_found() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();

    let result = delete_member(tmp.path(), "nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_save_member_content_incoming_new() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&incoming_dir).unwrap();

    save_member_content(
        tmp.path(),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();

    assert!(incoming_dir.join("alice.json").exists());
    let content = fs::read_to_string(incoming_dir.join("alice.json")).unwrap();
    assert!(content.contains("\"member_id\": \"alice\""));
}

#[test]
fn test_save_member_content_creates_directory_if_missing() {
    let tmp = TempDir::new().unwrap();

    save_member_content(
        tmp.path(),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();

    let content = fs::read_to_string(tmp.path().join("members/incoming/alice.json")).unwrap();
    assert!(content.contains("\"member_id\": \"alice\""));
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
        tmp.path(),
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
        tmp.path(),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
        true,
    )
    .unwrap();

    let content = fs::read_to_string(incoming_dir.join("alice.json")).unwrap();
    assert!(content.contains("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"));
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
        tmp.path(),
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
        tmp.path(),
        MemberStatus::Incoming,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("symlink"));
    assert!(
        !outside_dir.join("alice.json").exists(),
        "member file must not be written outside the workspace"
    );
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
        tmp.path(),
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
        tmp.path(),
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
        tmp.path(),
        MemberStatus::Active,
        "alice",
        &build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
        false,
    );
    let err = result.unwrap_err().to_string();

    assert!(err.contains("active/"));
}

#[test]
fn test_find_active_member_by_kid_returns_matching_member() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(
        active_dir.join("alice.json"),
        build_public_key_json("alice", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    )
    .unwrap();
    fs::write(
        active_dir.join("bob.json"),
        build_public_key_json("bob", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
    )
    .unwrap();

    let found = find_active_member_by_kid(tmp.path(), "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE")
        .unwrap()
        .unwrap();

    assert_eq!(found.protected.member_id, "bob");
}

fn build_public_key_json(member_id: &str, kid: &str) -> String {
    format!(
        r#"{{
  "protected": {{
    "format": "secretenv.public.key@4",
    "member_id": "{member_id}",
    "kid": "{kid}",
    "identity": {{
      "keys": {{
        "kem": {{"kty":"OKP","crv":"X25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
        "sig": {{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
      }},
      "attestation": {{
        "method": "ssh-sign",
        "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
      }}
    }},
    "created_at": "2026-01-01T00:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }},
  "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}}"#
    )
}

fn test_kid(index: usize) -> String {
    format!("7M2Q9D4R1H8VW6PKT3XNC5JY2F9A{:04X}", index)
}
