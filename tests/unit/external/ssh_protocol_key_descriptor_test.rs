// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use secretenv::io::ssh::protocol::key_descriptor::SshKeyDescriptor;

#[test]
fn test_from_path_detects_public_key() {
    let path = PathBuf::from("/path/to/id_ed25519.pub");
    let descriptor = SshKeyDescriptor::from_path(path);
    assert!(descriptor.is_public_key_file());
    assert!(!descriptor.is_private_key_file());
}

#[test]
fn test_from_path_detects_private_key() {
    let path = PathBuf::from("/path/to/id_ed25519");
    let descriptor = SshKeyDescriptor::from_path(path);
    assert!(descriptor.is_private_key_file());
    assert!(!descriptor.is_public_key_file());
}

#[test]
fn test_require_private_key() {
    let path = PathBuf::from("/path/to/id_ed25519");
    let descriptor = SshKeyDescriptor::from_path(path.clone());
    let private_key = descriptor.require_private_key().unwrap();
    assert_eq!(private_key.as_path(), path.as_path());
}

#[test]
fn test_require_private_key_rejects_public() {
    let path = PathBuf::from("/path/to/id_ed25519.pub");
    let descriptor = SshKeyDescriptor::from_path(path);
    let result = descriptor.require_private_key();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Signing requires a private key"));
    assert!(err_msg.contains("public key was provided"));
}

#[test]
fn test_as_path_private() {
    let path = PathBuf::from("/path/to/id_ed25519");
    let descriptor = SshKeyDescriptor::from_path(path.clone());
    assert_eq!(descriptor.as_path(), path.as_path());
}

#[test]
fn test_as_path_public() {
    let path = PathBuf::from("/path/to/id_ed25519.pub");
    let descriptor = SshKeyDescriptor::from_path(path.clone());
    assert_eq!(descriptor.as_path(), path.as_path());
}

#[test]
fn test_to_path_buf_private() {
    let path = PathBuf::from("/path/to/id_ed25519");
    let descriptor = SshKeyDescriptor::from_path(path.clone());
    assert_eq!(descriptor.to_path_buf(), path);
}

#[test]
fn test_to_path_buf_public() {
    let path = PathBuf::from("/path/to/id_ed25519.pub");
    let descriptor = SshKeyDescriptor::from_path(path.clone());
    assert_eq!(descriptor.to_path_buf(), path);
}

#[test]
fn test_require_public_key() {
    let path = PathBuf::from("/path/to/id_ed25519.pub");
    let descriptor = SshKeyDescriptor::from_path(path.clone());
    let public_key = descriptor.require_public_key().unwrap();
    assert_eq!(public_key.as_path(), path.as_path());
}

#[test]
fn test_require_public_key_rejects_private() {
    let path = PathBuf::from("/path/to/id_ed25519");
    let descriptor = SshKeyDescriptor::from_path(path);
    let result = descriptor.require_public_key();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Operation requires a public key"));
    assert!(err_msg.contains("private key was provided"));
}

#[test]
fn test_from_pathbuf() {
    let path = PathBuf::from("/path/to/id_ed25519");
    let descriptor: SshKeyDescriptor = path.clone().into();
    assert!(descriptor.is_private_key_file());
    assert_eq!(descriptor.to_path_buf(), path);

    let pub_path = PathBuf::from("/path/to/id_ed25519.pub");
    let pub_descriptor: SshKeyDescriptor = pub_path.clone().into();
    assert!(pub_descriptor.is_public_key_file());
    assert_eq!(pub_descriptor.to_path_buf(), pub_path);
}
