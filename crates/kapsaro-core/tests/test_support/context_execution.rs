// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use tempfile::TempDir;

use crate::test_utils::setup_member_key_context;
use kapsaro_core::api::key::KeyContext;
use kapsaro_core::api::workspace::WorkspaceWriteDirectories;
use kapsaro_core::service::member::approval::MemberApprovalSession;
use kapsaro_core::service::trust::{
    StrictKeyCheckingResolution, TrustCommandSession, WriteTrustOptions,
};

use super::TestCommandOptions;

pub(crate) struct TestWriteSession {
    pub(crate) directories: WorkspaceWriteDirectories,
    pub(crate) trust: TrustCommandSession,
    pub(crate) options: WriteTrustOptions,
}

pub(crate) fn build_test_trust_command_session(
    home: &TempDir,
    member_handle: &str,
) -> TrustCommandSession {
    TrustCommandSession::from_test_parts(
        home.path(),
        crate::test_utils::member_handle(member_handle),
        KeyContext::from_inner(setup_member_key_context(home, member_handle, None)),
    )
    .unwrap()
}

pub(crate) fn build_test_member_approval_session(
    home: &TempDir,
    member_handle: &str,
    workspace: &Path,
) -> MemberApprovalSession {
    MemberApprovalSession::open(
        workspace,
        build_test_trust_command_session(home, member_handle),
    )
    .unwrap()
}

pub(crate) fn resolve_test_write_session(
    options: &TestCommandOptions,
    member_handle: &str,
) -> TestWriteSession {
    let home = options.home.as_ref().expect("test command home");
    let trust = TrustCommandSession::from_test_parts(
        home,
        crate::test_utils::member_handle(member_handle),
        KeyContext::from_inner(crate::test_utils::setup_member_key_context_at(
            home,
            member_handle,
            None,
        )),
    )
    .unwrap();
    let directories =
        WorkspaceWriteDirectories::open(options.workspace.clone().expect("test write workspace"))
            .unwrap();
    TestWriteSession {
        directories,
        trust,
        options: WriteTrustOptions::new(
            options.allow_expired_key,
            true,
            StrictKeyCheckingResolution::strict(),
        ),
    }
}

pub(crate) fn build_test_trust_command_session_from_options(
    options: &TestCommandOptions,
    member_handle: &str,
) -> TrustCommandSession {
    resolve_test_write_session(options, member_handle).trust
}
