// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for which key the SSH signing identity of a command is chosen for.
//! Fixes that a named key is unlocked with the SSH key that protects it.

use std::fs;
use std::path::Path;

use super::{resolve_selected_key_ssh_fingerprint, resolve_ssh_context_for_member_key};
use crate::app::context::execution::set_post_ssh_key_resolution_hook;
use crate::app::context::options::CommonCommandOptions;
use crate::app_test_utils::build_test_command_options_with;
use crate::config::types::SshSigningMethod;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::model::identity::{Kid, MemberHandle};
use crate::test_utils::{
    build_test_private_key, generate_temp_ssh_keypair_in_dir, keygen_test,
    setup_test_keystore_from_fixtures, EnvGuard, ALICE_MEMBER_HANDLE,
};
use serial_test::serial;
use tempfile::TempDir;

/// Store one more key for a member, protected under an SSH key of its own.
///
/// The fixture keystore protects everything it holds with one SSH key, so a
/// second identity has to be brought in here for the two keys to differ in the
/// only respect these tests are about.
fn add_key_protected_by(
    home: &Path,
    member_handle: &str,
    ssh_private_key: &Path,
    ssh_public_key: &str,
) -> Kid {
    let (plaintext, public_key) =
        keygen_test(member_handle, ssh_private_key, ssh_public_key).unwrap();
    let kid = Kid::try_from(public_key.protected.kid.as_str()).unwrap();
    let private_key = build_test_private_key(
        &plaintext,
        member_handle,
        kid.as_str(),
        ssh_private_key,
        ssh_public_key,
    )
    .unwrap();
    let member = MemberHandle::try_from(member_handle).unwrap();
    KeystoreAccess::open(home.join("keys"))
        .unwrap()
        .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
        .unwrap();
    kid
}

fn active_ssh_public_key(home: &Path) -> String {
    fs::read_to_string(home.join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string()
}

fn open_keystore(home: &Path) -> KeystoreAccess {
    KeystoreAccess::open(home.join("keys")).unwrap()
}

/// A key the operator named is unlocked with the SSH key stored on that key.
///
/// This is what `decrypt --kid` turns on: the named key is protected under one
/// SSH identity and the member's active key under another, so an identity taken
/// from the active key would be handed to a key it cannot open.
#[test]
fn test_a_named_key_is_unlocked_with_the_ssh_key_stored_on_it() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let other_ssh = TempDir::new().unwrap();
    let (other_private, _, other_public) = generate_temp_ssh_keypair_in_dir(&other_ssh);
    let named_kid = add_key_protected_by(
        home.path(),
        ALICE_MEMBER_HANDLE,
        &other_private,
        &other_public,
    );
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();

    let (_, fingerprint) = resolve_selected_key_ssh_fingerprint(
        &open_keystore(home.path()),
        &member,
        Some(named_kid.as_str()),
    )
    .unwrap();

    assert_eq!(
        fingerprint,
        build_sha256_fingerprint(&other_public).unwrap()
    );
}

/// A command that names no key is unlocked with the SSH key of the active one,
/// whatever other keys the member holds.
#[test]
fn test_a_command_that_names_no_key_uses_the_active_key_ssh_identity() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let other_ssh = TempDir::new().unwrap();
    let (other_private, _, other_public) = generate_temp_ssh_keypair_in_dir(&other_ssh);
    add_key_protected_by(
        home.path(),
        ALICE_MEMBER_HANDLE,
        &other_private,
        &other_public,
    );
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();

    let (_, fingerprint) =
        resolve_selected_key_ssh_fingerprint(&open_keystore(home.path()), &member, None).unwrap();

    assert_eq!(
        fingerprint,
        build_sha256_fingerprint(&active_ssh_public_key(home.path())).unwrap()
    );
}

/// Options that offer exactly one SSH identity: the one the fixture keystore
/// protects the member's active key with.
fn options_offering_the_active_ssh_identity(home: &Path) -> CommonCommandOptions {
    build_test_command_options_with(
        home,
        None,
        Some(&home.join(".ssh").join("test_ed25519")),
        false,
        Some(SshSigningMethod::SshKeygen),
    )
}

/// Resolving the whole signing environment carries the named key down too.
///
/// This is what `key export --private --kid` turns on: the export unwraps the
/// key the operator named, so the SSH identity has to be the one stored on that
/// key. The only identity on offer here protects the active key, so a context
/// still chosen for the active key would be built without complaint and the
/// export would then fail to decrypt the key it was actually asked for.
#[test]
#[serial]
fn test_the_signing_environment_is_resolved_for_the_named_key() {
    let _env = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    std::env::remove_var("KAPSARO_HOME");
    std::env::remove_var("KAPSARO_WORKSPACE");

    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let other_ssh = TempDir::new().unwrap();
    let (other_private, _, other_public) = generate_temp_ssh_keypair_in_dir(&other_ssh);
    let named_kid = add_key_protected_by(
        home.path(),
        ALICE_MEMBER_HANDLE,
        &other_private,
        &other_public,
    );
    let options = options_offering_the_active_ssh_identity(home.path());

    // The resolution carries a signature backend, which no `Debug` reaches, so
    // the failure is taken by matching rather than by unwrapping.
    let error = match resolve_ssh_context_for_member_key(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        Some(named_kid.as_str()),
    ) {
        Ok(_) => panic!("the offered identity does not protect the named key"),
        Err(error) => error,
    };

    let message = error.format_user_message();
    assert!(
        message.contains(&build_sha256_fingerprint(&other_public).unwrap()),
        "{message}"
    );
}

/// The active KID selected for the SSH fingerprint is the KID the loader uses,
/// even when activation changes before the private key is opened.
#[test]
#[serial]
fn test_execution_loads_the_kid_selected_for_the_ssh_context() {
    let _env = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    std::env::remove_var("KAPSARO_HOME");
    std::env::remove_var("KAPSARO_WORKSPACE");

    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = open_keystore(home.path());
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let selected_kid = access.load_active_kid(&member).unwrap().unwrap();
    let public_key = active_ssh_public_key(home.path());
    let replacement_kid = add_key_protected_by(
        home.path(),
        ALICE_MEMBER_HANDLE,
        &home.path().join(".ssh/test_ed25519"),
        &public_key,
    );
    access
        .activate_existing_key(&member, &selected_kid)
        .unwrap();
    let hook_access = access.clone();
    let hook_member = member.clone();
    let hook_kid = replacement_kid.clone();
    set_post_ssh_key_resolution_hook(move || {
        hook_access
            .activate_existing_key(&hook_member, &hook_kid)
            .unwrap();
    });
    let options = options_offering_the_active_ssh_identity(home.path());

    let execution = crate::app::context::execution::resolve_read_execution(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
    )
    .unwrap();

    assert_eq!(execution.key_ctx.kid(), &selected_kid);
    assert_eq!(
        access.load_active_kid(&member).unwrap(),
        Some(replacement_kid)
    );
}
