// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public file input reads retain independent positions when shared by callers.
//! Exercises plaintext and import readers against the same opened file.

use std::path::Path;
use std::sync::Barrier;
use std::thread;

use kapsaro_core::api::file::{
    load_plaintext_bytes, FileEncArtifact, FileInputTarget, FileReadOperation,
};
use kapsaro_core::api::key::{KeyContext, KeyContextOptions, LocalKeyStore, MemberHandle};
use kapsaro_core::api::kv::load_import_text;
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::secret::SecretBytes;
use kapsaro_core::api::ssh::{SshRawSignature, SshSignatureBackend};
use kapsaro_core::api::trust::{
    CurrentMemberSnapshot, FileReadTarget, ReadSessionDecision, ReadTrustExceptions, TrustDecision,
    TrustPolicyEvaluator, WorkspaceReadSession,
};
use kapsaro_core::test_support::storage::ssh::backend::SignatureBackend;

use crate::test_utils::ed25519_backend::Ed25519DirectBackend;
use crate::test_utils::{
    open_test_workspace, setup_test_workspace_from_fixtures, ALICE_MEMBER_HANDLE,
};

const INPUT_SIZE: usize = 8 * 1024 * 1024;
const READER_COUNT: usize = 8;

#[derive(Clone, Copy)]
enum InputReadMode {
    Plaintext,
    Import,
    Mixed,
}

#[test]
fn test_shared_file_input_plaintext_reads_return_complete_content() {
    assert_concurrent_input_reads(InputReadMode::Plaintext);
}

#[test]
fn test_shared_file_input_import_reads_return_complete_content() {
    assert_concurrent_input_reads(InputReadMode::Import);
}

#[test]
fn test_shared_file_input_mixed_reads_return_complete_content() {
    assert_concurrent_input_reads(InputReadMode::Mixed);
}

fn assert_concurrent_input_reads(mode: InputReadMode) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.env");
    let content: Vec<u8> = (0..INPUT_SIZE)
        .map(|index| b'a' + ((index / 97 + index) % 26) as u8)
        .collect();
    std::fs::write(&path, &content).unwrap();
    let target = FileInputTarget::open(&path, None).unwrap();
    let barrier = Barrier::new(READER_COUNT);

    thread::scope(|scope| {
        let readers: Vec<_> = (0..READER_COUNT)
            .map(|index| {
                let target = &target;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    match mode {
                        InputReadMode::Plaintext => load_plaintext_bytes(target),
                        InputReadMode::Import => load_import_text(target).map(String::into_bytes),
                        InputReadMode::Mixed if index % 2 == 0 => load_plaintext_bytes(target),
                        InputReadMode::Mixed => load_import_text(target).map(String::into_bytes),
                    }
                })
            })
            .collect();
        for reader in readers {
            let loaded = reader.join().unwrap().unwrap();
            assert_eq!(loaded.len(), content.len());
            assert!(
                loaded == content,
                "each reader must return every byte in order"
            );
        }
    });
}

#[test]
fn test_shared_file_input_and_read_target_verify_and_decrypt_complete_content() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_store = LocalKeyStore::open(home.path().join("keys")).unwrap();
    let key_ctx = load_fixture_key_context(home.path(), &key_store);
    let recipient = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let recipients = key_store.load_recipient_keys([recipient]).unwrap();
    let plaintext = vec![b'x'; 1024 * 1024];
    let artifact = FileEncArtifact::encrypt_bytes(&plaintext, &recipients, &key_ctx).unwrap();
    let path = workspace.join("concurrent.enc");
    std::fs::write(&path, artifact.as_str()).unwrap();
    let input = FileInputTarget::open(&path, None).unwrap();
    let access = open_test_workspace(&workspace);
    let session = WorkspaceReadSession::open_with_local_state(
        &access,
        None,
        &key_ctx,
        OperationOptions::default(),
    )
    .unwrap();
    let target = session.open_file_read_target(&input).unwrap();
    let barrier = Barrier::new(READER_COUNT);
    thread::scope(|scope| {
        for index in 0..READER_COUNT {
            let (input, target, home, workspace) = (&input, &target, home.path(), &workspace);
            let (barrier, plaintext) = (&barrier, &plaintext);
            scope.spawn(move || {
                let actual = decrypt_concurrent_input(
                    home,
                    workspace,
                    input,
                    target,
                    barrier,
                    index % 2 == 0,
                );
                assert!(actual.expose_secret() == plaintext);
            });
        }
    });
}

fn decrypt_concurrent_input(
    home: &Path,
    workspace: &Path,
    input: &FileInputTarget,
    target: &FileReadTarget,
    barrier: &Barrier,
    direct: bool,
) -> SecretBytes {
    let key_store = LocalKeyStore::open(home.join("keys")).unwrap();
    let key_ctx = load_fixture_key_context(home, &key_store);
    let access = open_test_workspace(workspace);
    let session = WorkspaceReadSession::open_with_local_state(
        &access,
        None,
        &key_ctx,
        OperationOptions::default(),
    )
    .unwrap();
    let evaluator = TrustPolicyEvaluator::new(CurrentMemberSnapshot::load(&access).unwrap(), None);
    barrier.wait();
    if direct {
        return decrypt_input(input, &key_ctx, &evaluator);
    }
    let decision = session
        .begin_file_read(target, FileReadOperation::Decrypt, false)
        .unwrap();
    let ReadSessionDecision::Authorized(authorized) = decision else {
        panic!("self-signed fixture must be authorized");
    };
    authorized.value().decrypt_bytes().unwrap()
}

fn decrypt_input(
    input: &FileInputTarget,
    key_ctx: &KeyContext,
    evaluator: &TrustPolicyEvaluator,
) -> SecretBytes {
    let artifact = FileEncArtifact::parse(load_import_text(input).unwrap()).unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let decision = evaluator
        .evaluate_file(
            &verified,
            key_ctx,
            FileReadOperation::Decrypt,
            OperationOptions::default(),
            ReadTrustExceptions::none(),
        )
        .unwrap();
    let TrustDecision::Trusted(trusted) = decision else {
        panic!("self-signed fixture must be trusted");
    };
    trusted.decrypt_bytes().unwrap()
}

struct FixtureSshBackend(Ed25519DirectBackend);

impl SshSignatureBackend for FixtureSshBackend {
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> kapsaro_core::Result<SshRawSignature> {
        self.0
            .sign_sshsig(namespace, ssh_pubkey, message)
            .map(|signature| SshRawSignature::new(*signature.as_bytes()))
    }
}

fn load_fixture_key_context(home: &Path, key_store: &LocalKeyStore) -> KeyContext {
    let backend = Ed25519DirectBackend::new(&home.join(".ssh/test_ed25519")).unwrap();
    let ssh_pubkey = std::fs::read_to_string(home.join(".ssh/test_ed25519.pub")).unwrap();
    key_store
        .load_key_context(KeyContextOptions::new(
            MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap(),
            Box::new(FixtureSshBackend(backend)),
            ssh_pubkey.trim().to_string(),
        ))
        .unwrap()
}
