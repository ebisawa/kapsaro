// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::fs;
use tempfile::TempDir;

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
        tmp.path(),
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
        tmp.path(),
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

fn build_public_key_json(member_handle: &str, kid: &str) -> String {
    format!(
        r#"{{
  "protected": {{
    "format": "secretenv:format:public-key@6",
    "subject_handle": "{member_handle}",
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
  "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}}"#
    )
}
