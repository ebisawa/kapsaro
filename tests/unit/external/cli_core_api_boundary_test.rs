// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn cli_api_test_support_is_hidden_and_feature_gated() {
    let root = cli_api_root_source();
    let test_support = cli_api_test_support_source();

    assert!(root.contains("#[cfg(any(feature = \"cli-test-support\", test))]"));
    assert!(root.contains("#[doc(hidden)]"));
    assert!(root.contains("pub mod test_support;"));

    for new_root in [
        "pub mod settings {",
        "pub mod primitives {",
        "pub mod operations {",
        "pub mod wire {",
        "pub mod storage {",
        "pub mod domain {",
        "pub mod helpers {",
    ] {
        assert!(
            test_support.contains(new_root),
            "test_support is missing redesigned root: {new_root}"
        );
    }
}

#[test]
fn cli_api_uses_explicit_allow_lists() {
    let root = cli_api_root_source();
    let app = cli_api_app_source();
    let presentation = cli_api_presentation_source();
    let test_support = cli_api_test_support_source();
    let content = cli_api_combined_source();

    assert!(root.contains("pub mod app;"));
    assert!(root.contains("pub mod presentation;"));
    assert!(root.contains("pub mod test_support;"));
    assert!(app.contains("pub mod context {"));
    assert!(app.contains("pub mod file {"));
    assert!(app.contains("pub mod kv {"));
    assert!(app.contains("pub mod trust {"));
    assert!(app.contains("execute_decrypt_file_command"));
    assert!(app.contains("execute_inspect_file_command"));
    assert!(app.contains("InspectOutput, InspectSection"));
    assert!(presentation.contains("pub use crate::support::fs::atomic::{save_bytes, save_text};"));
    assert!(test_support.contains("pub mod settings {"));
    assert!(content.contains("pub use crate::app::kv::types::{"));
    assert!(
        content.contains("use crate::api::kv::KvInputEntry as ApiKvInputEntry;"),
        "cli_api app set command bridge must take public api KV entries"
    );
}

#[test]
fn api_module_does_not_flat_reexport_facades() {
    let content =
        fs::read_to_string("crates/kapsaro-core/src/api/mod.rs").expect("read api source");

    assert!(
        !content.contains("pub use "),
        "api/mod.rs must keep canonical module paths instead of flat re-exports"
    );
}

#[test]
fn cli_api_test_support_keeps_single_canonical_paths() {
    let test_support = cli_api_test_support_source();

    assert_absent(
        &test_support,
        "pub mod signature_backend {",
        "SignatureBackend must be exposed only through storage::ssh::backend",
    );
    assert_absent(
        &test_support,
        "pub use crate::io::ssh::protocol::{",
        "SSH protocol helpers must be exposed through their purpose-specific modules",
    );
    assert_absent(
        &test_support,
        "pub use crate::io::ssh::protocol::build_sha256_fingerprint",
        "build_sha256_fingerprint must use storage::ssh::protocol::fingerprint",
    );
    assert_absent(
        &test_support,
        "pub use crate::io::ssh::protocol::SshKeyDescriptor",
        "SshKeyDescriptor must use storage::ssh::protocol::key_descriptor",
    );
    assert_absent(
        &test_support,
        "pub use crate::io::ssh::backend::signature_backend::SignatureBackend",
        "SignatureBackend must not be duplicated under signature_backend",
    );
    assert_absent(
        &test_support,
        "pub mod bootstrap {",
        "member handle validation must be exposed through helpers::validation",
    );
    assert_absent(
        &test_support,
        "::*;",
        "test_support must use explicit re-export allow-lists",
    );
}

#[test]
fn cli_api_does_not_reintroduce_broad_test_support_exports() {
    let test_support = cli_api_test_support_source();

    for obsolete_export in [
        "build_crypto_operation_error",
        "sign_artifact_bytes",
        "verify_artifact_bytes",
        "AsHkdfSalt",
        "load_global_config",
        "ConfigValueResolution",
        "DecryptionResult",
        "EnvKeyLoadResult",
        "VerifiedExpiresAt",
        "verify_kv_signature",
        "unwrap_master_key_for_kv",
        "build_wrap_item,",
        "IntoKnownKid",
        "find_recipient_handle_mismatch",
        "extract_kv_header_tokens",
        "parse_private_key_str",
        "resolve_github_account_by_login;",
        "select_latest_valid_kid",
        "find_member_by_kid",
        "load_ssh_key_candidate_from_file",
        "SSHSIG_ARMOR_BEGIN",
        "validate_sshsig_inputs",
        "verify_github_account;",
        "normalize_recipients",
        "decode_base64url_nopad_ciphertext",
        "SecretEnvironmentMap",
        "PortableExportOutput",
        "ActiveKeyDocument",
        "TrustStoreLoadResult",
        "RecipientWrap",
    ] {
        assert_absent(
            &test_support,
            obsolete_export,
            "test_support must keep a narrow purpose-based allow-list",
        );
    }
}

#[test]
fn core_internal_roots_do_not_keep_dead_convenience_reexports() {
    let cases = [
        (
            "crates/kapsaro-core/src/feature/trust/judgment.rs",
            [
                "CurrentMemberMatch",
                "KnownKeyMatch",
                "",
                "",
                "",
                "",
                "",
                "",
            ],
        ),
        (
            "crates/kapsaro-core/src/io/workspace/detection.rs",
            ["resolve_workspace_with_base,", "", "", "", "", "", "", ""],
        ),
        (
            "crates/kapsaro-core/src/io/workspace/members.rs",
            [
                "promote_incoming_members,",
                "find_active_member_by_kid,",
                "list_member_file_paths,",
                "load_active_member_index_by_kid,",
                "",
                "",
                "",
                "",
            ],
        ),
        (
            "crates/kapsaro-core/src/io/workspace/members/store.rs",
            [
                "find_active_member_by_kid,",
                "list_member_file_paths,",
                "load_active_member_index_by_kid,",
                "",
                "",
                "",
                "",
                "",
            ],
        ),
        (
            "crates/kapsaro-core/src/support/fs.rs",
            [
                "check_permission,",
                "load_bytes_with_limit,",
                "ensure_text_file_matches_snapshot,",
                "",
                "",
                "",
                "",
                "",
            ],
        ),
    ];

    for (path, obsolete_exports) in cases {
        let content = fs::read_to_string(path).expect("read core source");
        for obsolete_export in obsolete_exports
            .into_iter()
            .filter(|value| !value.is_empty())
        {
            assert_absent(
                &content,
                obsolete_export,
                "core internal root must avoid unused convenience re-exports",
            );
        }
    }
}

#[test]
fn internal_helper_results_are_not_public_surface() {
    let cases = [(
        "crates/kapsaro-core/src/feature/key/portable_export.rs",
        "pub struct PortableExportOutput",
    )];

    for (path, obsolete_visibility) in cases {
        let content = fs::read_to_string(path).expect("read core source");
        assert_absent(
            &content,
            obsolete_visibility,
            "internal helper result types must not be public surface",
        );
    }
}

#[test]
fn production_cli_uses_only_allowed_core_boundaries() {
    for path in rust_files_under(Path::new("src")) {
        let content = fs::read_to_string(&path).expect("read production source");
        let display_path = path.display();

        assert!(
            !content.contains("kapsaro_core::cli_api::test_support"),
            "{display_path} must not use hidden test support"
        );

        for root in [
            "app", "config", "crypto", "feature", "format", "io", "model", "support",
        ] {
            let direct_path = format!("kapsaro_core::{root}::");
            assert!(
                !content.contains(&direct_path),
                "{display_path} must use cli_api/app or cli_api/presentation instead of {direct_path}"
            );
        }

        assert_core_alias_does_not_reach_hidden_surface(&content, &path);
    }
}

#[test]
fn secret_inputs_use_api_facade_boundary() {
    let set = fs::read_to_string("src/cli/set.rs").expect("read set command source");
    let key_operations =
        fs::read_to_string("src/cli/key/operations.rs").expect("read key operations source");

    for (display_path, content) in [
        ("src/cli/set.rs", set.as_str()),
        ("src/cli/key/operations.rs", key_operations.as_str()),
    ] {
        assert_absent(
            content,
            "cli_api::presentation::secret::SecretString",
            "production CLI secret-bearing input must use the public API facade boundary",
        );
        assert!(
            content.contains("api::secret::SecretString"),
            "{display_path} must make the secret input boundary explicit"
        );
    }
}

#[test]
fn cli_api_does_not_reexport_redundant_secret_or_kv_input_facades() {
    let app = cli_api_app_source();
    let presentation = cli_api_presentation_source();

    assert_absent(
        &presentation,
        "pub mod secret",
        "production CLI must use api::secret for secret-bearing input",
    );
    assert_absent(
        &app,
        "KvInputEntry,",
        "cli_api::app::kv::types must not re-export KV input entries",
    );
    assert!(
        app.contains("use crate::api::kv::KvInputEntry as ApiKvInputEntry;"),
        "set command bridge must keep public api KV input as the boundary"
    );
}

#[test]
fn app_cli_boundary_does_not_expose_online_io_status() {
    let cli_app = cli_api_app_source();
    let key_types = fs::read_to_string("crates/kapsaro-core/src/app/key/types.rs")
        .expect("read app key types source");
    let registration_types =
        fs::read_to_string("crates/kapsaro-core/src/app/registration/types.rs")
            .expect("read app registration types source");

    for (display_path, content) in [
        ("crates/kapsaro-core/src/cli_api/app.rs", cli_app.as_str()),
        (
            "crates/kapsaro-core/src/app/key/types.rs",
            key_types.as_str(),
        ),
        (
            "crates/kapsaro-core/src/app/registration/types.rs",
            registration_types.as_str(),
        ),
    ] {
        assert_absent(
            content,
            "crate::io::verify_online::VerificationStatus",
            &format!("{display_path} must expose app-owned online verification status"),
        );
    }

    assert_absent(
        &cli_app,
        "KeyRemoveResult, OnlineVerificationStatus",
        "cli_api::app::key::types must not re-export online status when api::online owns the public path",
    );
    assert_absent(
        &cli_app,
        "MemberKeySetupResult, OnlineVerificationStatus",
        "cli_api::app::registration::types must not re-export online status when api::online owns the public path",
    );
}

#[test]
fn production_cli_uses_api_online_status_boundary() {
    let key_text =
        fs::read_to_string("src/cli/common/output/text/key.rs").expect("read key text source");

    assert!(
        key_text.contains("use kapsaro_core::api::online::OnlineVerificationStatus;"),
        "key text output must use the public api::online status boundary"
    );
    assert_absent(
        &key_text,
        "cli_api::app::key::types::OnlineVerificationStatus",
        "production CLI must not depend on cli_api online status re-exports",
    );
}

#[test]
fn feature_member_layer_does_not_own_file_or_online_io() {
    let member_add = fs::read_to_string("crates/kapsaro-core/src/feature/member/add.rs")
        .expect("read feature member add source");
    let member_verification =
        fs::read_to_string("crates/kapsaro-core/src/feature/member/verification.rs")
            .expect("read feature member verification source");

    for (display_path, content) in [
        (
            "crates/kapsaro-core/src/feature/member/add.rs",
            member_add.as_str(),
        ),
        (
            "crates/kapsaro-core/src/feature/member/verification.rs",
            member_verification.as_str(),
        ),
    ] {
        for forbidden in [
            "load_text_with_limit",
            "save_member_content",
            "load_member_file_from_path",
            "verify_github_account(",
        ] {
            assert_absent(
                content,
                forbidden,
                &format!("{display_path} must keep file and online I/O in app/io"),
            );
        }
    }
}

#[test]
fn public_entrypoints_do_not_keep_redundant_modules() {
    let content =
        fs::read_to_string("crates/kapsaro-core/src/lib.rs").expect("read core lib source");

    assert!(
        content.contains("\nmod error;"),
        "error implementation must stay private behind root error re-exports"
    );
    assert!(
        content.contains("pub use error::{Error, ErrorKind, Result};"),
        "root error re-exports must remain the stable error surface"
    );
    for redundant_module in ["pub mod prelude;", "pub mod error;"] {
        assert!(
            !content.contains(redundant_module),
            "core public surface must use canonical api modules and root error exports"
        );
    }
}

#[test]
fn cli_api_app_does_not_reexport_feature_dtos() {
    let app = cli_api_app_source();

    assert_absent(
        &app,
        "pub use crate::feature::kv::types::KvInputEntry",
        "cli_api::app must expose app-owned DTOs instead of feature DTOs",
    );
    assert_absent(
        &app,
        "KvInputEntry,",
        "cli_api::app::kv::types must not expose KV input DTOs; use api::kv::KvInputEntry",
    );
}

#[test]
fn online_test_support_modules_are_feature_gated() {
    let content = cli_api_test_support_source();

    assert!(
        module_is_absent_or_feature_gated(&content, "pub mod account {"),
        "github account test-support module must be gated as a whole if present"
    );
    assert!(
        module_is_feature_gated(&content, "pub mod github {"),
        "online verification github test-support module must be gated as a whole"
    );
}

#[test]
fn implementation_roots_stay_crate_private() {
    let content =
        fs::read_to_string("crates/kapsaro-core/src/lib.rs").expect("read core lib source");

    assert!(content.contains("\nmod app;"));

    for root in [
        "config", "crypto", "feature", "format", "io", "model", "support",
    ] {
        assert!(
            content.contains(&format!("pub(crate) mod {root};")),
            "{root} must remain crate-private"
        );
        assert!(
            !content.contains(&format!("\npub mod {root};")),
            "{root} must not become a public implementation root"
        );
    }
}

fn cli_api_root_source() -> String {
    fs::read_to_string("crates/kapsaro-core/src/cli_api.rs").expect("read cli_api root source")
}

fn cli_api_app_source() -> String {
    fs::read_to_string("crates/kapsaro-core/src/cli_api/app.rs").expect("read cli_api app source")
}

fn cli_api_presentation_source() -> String {
    fs::read_to_string("crates/kapsaro-core/src/cli_api/presentation.rs")
        .expect("read cli_api presentation source")
}

fn cli_api_test_support_source() -> String {
    fs::read_to_string("crates/kapsaro-core/src/cli_api/test_support.rs")
        .expect("read cli_api test_support source")
}

fn cli_api_combined_source() -> String {
    [
        cli_api_root_source(),
        cli_api_app_source(),
        cli_api_presentation_source(),
        cli_api_test_support_source(),
    ]
    .join("\n")
}

fn module_is_feature_gated(content: &str, module_header: &str) -> bool {
    content
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|window| {
            window[0].trim() == "#[cfg(feature = \"online\")]" && window[1].trim() == module_header
        })
}

fn module_is_absent_or_feature_gated(content: &str, module_header: &str) -> bool {
    !content.lines().any(|line| line.trim() == module_header)
        || module_is_feature_gated(content, module_header)
}

fn assert_absent(content: &str, needle: &str, message: &str) {
    assert!(!content.contains(needle), "{message}: {needle}");
}

fn rust_files_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files);
    files
}

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_dir() {
        for entry in fs::read_dir(path).expect("read source directory") {
            collect_rust_files(&entry.expect("read source entry").path(), files);
        }
        return;
    }

    if path.extension().is_some_and(|extension| extension == "rs") {
        files.push(path.to_path_buf());
    }
}

#[test]
fn test_cli_api_app_allow_list_snapshot() {
    let source = cli_api_app_source();
    let actual = extract_allow_list_snapshot(&source);
    let expected: &[&str] = &[
        "config::ConfigScope",
        "config::ConfigSetResult",
        "config::ConfigUnsetResult",
        "config::list_config_command",
        "config::resolve_config_value_command",
        "config::set_config_command",
        "config::unset_config_command",
        "context::env_key::is_env_key_mode",
        "context::execution::ExecutionContext",
        "context::execution::resolve_write_execution",
        "context::identity::build_missing_member_handle_error",
        "context::identity::resolve_github_user_input",
        "context::identity::resolve_member_handle_input",
        "context::member::resolve_required_member",
        "context::options::CommonCommandOptions",
        "context::options::resolve_allow_expired_key_option",
        "context::options::resolve_allow_non_member_option",
        "context::ssh::SshKeyCandidateView",
        "context::ssh::SshSigningContextResolution",
        "context::ssh::build_ssh_signing_context",
        "context::ssh::resolve_ssh_context_by_active_key",
        "context::ssh::resolve_ssh_key_candidates",
        "doctor::DoctorRequest",
        "doctor::execute_doctor_command",
        "doctor::types::DoctorCategory",
        "doctor::types::DoctorCheck",
        "doctor::types::DoctorReport",
        "doctor::types::DoctorStatus",
        "doctor::types::DoctorSubject",
        "file::decrypt::DecryptFileCommand",
        "file::decrypt::execute_decrypt_file_command",
        "file::decrypt::resolve_decrypt_file_command",
        "file::decrypt::validate_decrypt_file_input",
        "file::encrypt::EncryptFileCommand",
        "file::encrypt::execute_encrypt_file_command_with_recipient_set_confirmation",
        "file::encrypt::resolve_encrypt_file_command",
        "file::inspect::InspectCommand",
        "file::inspect::InspectOutput",
        "file::inspect::InspectSection",
        "file::inspect::execute_inspect_file_command",
        "key::generate::generate_key_command",
        "key::manage::activate_key_command",
        "key::manage::export_key_command",
        "key::manage::export_private_key_command",
        "key::manage::list_keys_command",
        "key::manage::remove_key_command",
        "key::manage::validate_kid",
        "key::types::KeyActivateResult",
        "key::types::KeyExportPrivateResult",
        "key::types::KeyExportResult",
        "key::types::KeyGenerationResult",
        "key::types::KeyInfo",
        "key::types::KeyListResult",
        "key::types::KeyRemoveResult",
        "kv::mutation::MutationWriteTrustPlan",
        "kv::mutation::import_kv_command_with_recipient_set_confirmation",
        "kv::mutation::resolve_mutation_write_plan",
        "kv::mutation::set_kv_command_with_recipient_set_confirmation",
        "kv::mutation::unset_kv_command_with_recipient_set_confirmation",
        "kv::query::KvReadCommand",
        "kv::query::execute_kv_list_command",
        "kv::query::execute_kv_read_command",
        "kv::query::resolve_kv_read_command",
        "kv::types::KvDisclosedEntry",
        "kv::types::KvImportResult",
        "kv::types::KvReadMode",
        "kv::types::KvReadResult",
        "kv::types::KvWriteOutcome",
        "member::approval::MemberApprovalEvaluation",
        "member::approval::MemberApprovalResult",
        "member::approval::evaluate_members_for_approval",
        "member::approval::save_member_approvals",
        "member::mutation::add_member",
        "member::mutation::evaluate_member_removal",
        "member::mutation::remove_member",
        "member::query::list_members",
        "member::query::load_member_show_result",
        "member::types::MemberDocumentStatus",
        "member::types::MemberDocumentView",
        "member::types::MemberGithubClaim",
        "member::types::MemberListEntry",
        "member::types::MemberListResult",
        "member::types::MemberRemovalReport",
        "member::types::MemberRemoveResult",
        "member::types::MemberShowResult",
        "member::types::MemberVerificationResult",
        "member::types::MembershipStatus",
        "member::verification::verify_members",
        "registration::InitWorkspaceState",
        "registration::command::RegistrationDecision",
        "registration::command::evaluate_registration_decision",
        "registration::command::execute_registration_decision",
        "registration::command::resolve_registration_command",
        "registration::ensure_init_workspace_structure",
        "registration::evaluate_init_workspace_status",
        "registration::key_plan::resolve_registration_key_plan",
        "registration::types::MemberKeySetupResult",
        "registration::types::RegistrationCommand",
        "registration::types::RegistrationKeyPlan",
        "registration::types::RegistrationMode",
        "registration::types::RegistrationOutcome",
        "registration::types::RegistrationResult",
        "registration::types::RegistrationTarget",
        "rewrap::RewrapBatchCommandInput",
        "rewrap::execute_rewrap_batch_command",
        "rewrap::promotion::PromotionReviewFailure",
        "rewrap::promotion::PromotionReviewPrompt",
        "rewrap::promotion::PromotionReviewView",
        "rewrap::types::RewrapBatchOutcome",
        "run::execute_run_command",
        "trust::ArtifactRecipientTrustOutcome",
        "trust::CommandCapability",
        "trust::GetPolicy",
        "trust::ImportPolicy",
        "trust::ListPolicy",
        "trust::RecipientTrustOutcome",
        "trust::RunPolicy",
        "trust::SetPolicy",
        "trust::SignerTrustOutcome",
        "trust::TrustApprovalCandidate",
        "trust::UnsetPolicy",
        "trust::WriteTrustPolicy",
        "trust::enforcement::ArtifactRecipientHandleHint",
        "trust::enforcement::ArtifactRecipientSetReview",
        "trust::enforcement::ArtifactRecipientSetSnapshot",
        "trust::list::RecipientSetListItem",
        "trust::list::RecipientSetListResult",
        "trust::list::TrustListItem",
        "trust::list::TrustListResult",
        "trust::list::list_known_keys",
        "trust::list::list_recipient_sets",
        "trust::management::PurgeKnownKeysResult",
        "trust::management::PurgeRecipientSetsResult",
        "trust::management::RemoveKnownKeyResult",
        "trust::management::RemoveRecipientSetResult",
        "trust::management::execute_purge",
        "trust::management::execute_recipient_set_purge",
        "trust::management::list_purge_candidates",
        "trust::management::list_recipient_set_purge_candidates",
        "trust::management::remove_known_key_command",
        "trust::management::remove_recipient_set_command",
        "trust::recovery::TrustStoreResetPlan",
        "trust::recovery::build_trust_store_reset_plan",
        "trust::recovery::execute_trust_store_reset",
        "trust::recovery::requires_trust_store_reset",
        "trust::review::ReadSignerTrustReviewPlan",
        "trust::review::SignerTrustLabels",
        "trust::review::TrustExecutionContext",
        "trust::review::WriteRecipientTrustReviewPlan",
        "trust::review::execute_read_with_signer_trust",
        "trust::review::execute_write_with_recipient_trust",
    ];
    assert_allow_list_matches(&actual, expected, "cli_api/app.rs");
}

#[test]
fn test_cli_api_presentation_allow_list_snapshot() {
    let source = cli_api_presentation_source();
    let actual = extract_allow_list_snapshot(&source);
    let expected: &[&str] = &[
        "config::SshSigningMethod",
        "fs::load_bytes",
        "fs::load_text_with_limit",
        "fs::save_bytes",
        "fs::save_text",
        "kid::format_kid_display",
        "kid::format_kid_display_lossy",
        "limits::MAX_JSON_DOCUMENT_READ_SIZE",
        "limits::MAX_KV_ENC_FILE_SIZE",
        "path::format_path_relative_to_cwd",
        "ssh::SshDeterminismStatus",
        "tty::is_interactive",
        "validation::validate_github_login",
        "validation::validate_member_handle",
    ];
    assert_allow_list_matches(&actual, expected, "cli_api/presentation.rs");
}

// Extracts the sorted allow-list snapshot from a cli_api source file.
// Returns entries in "mod::path::Name" format, sorted lexicographically.
fn extract_allow_list_snapshot(source: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut mod_stack: Vec<String> = Vec::new();
    let mut brace_depth_stack: Vec<i32> = Vec::new();
    let mut current_depth: i32 = 0;
    let mut use_buf = String::new();
    let mut in_use_stmt = false;

    for line in source.lines() {
        let trimmed = line.trim();
        // Start buffering before update_mod_stack so use-statement braces
        // do not corrupt the module depth counter.
        if !in_use_stmt && trimmed.starts_with("pub use ") {
            in_use_stmt = true;
        }
        if !in_use_stmt {
            update_mod_stack(
                trimmed,
                &mut mod_stack,
                &mut brace_depth_stack,
                &mut current_depth,
            );
        }
        if in_use_stmt {
            if !use_buf.is_empty() {
                use_buf.push(' ');
            }
            use_buf.push_str(trimmed);
            if trimmed.ends_with(';') {
                in_use_stmt = false;
                flush_use_stmt(&use_buf, &mod_stack, &mut entries);
                use_buf.clear();
            }
        } else {
            collect_pub_fn_name(trimmed, &mod_stack, &mut entries);
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

// Updates the module path stack as module braces open and close.
fn update_mod_stack(
    trimmed: &str,
    mod_stack: &mut Vec<String>,
    brace_depth_stack: &mut Vec<i32>,
    current_depth: &mut i32,
) {
    if let Some(rest) = trimmed.strip_prefix("pub mod ") {
        if let Some(name) = rest.split('{').next().map(|s| s.trim().to_string()) {
            mod_stack.push(name);
            brace_depth_stack.push(*current_depth);
        }
    }
    for ch in trimmed.chars() {
        match ch {
            '{' => *current_depth += 1,
            '}' => {
                *current_depth -= 1;
                if brace_depth_stack.last() == Some(current_depth) {
                    brace_depth_stack.pop();
                    mod_stack.pop();
                }
            }
            _ => {}
        }
    }
}

// Parses a complete `pub use path::{A, B};` or `pub use path::X;` statement
// and appends qualified entries to the list.
fn flush_use_stmt(stmt: &str, mod_stack: &[String], entries: &mut Vec<String>) {
    let prefix = mod_stack.join("::");
    let inner = stmt
        .trim_start_matches("pub use ")
        .trim_end_matches(';')
        .trim();
    let names = extract_use_names(inner);
    for name in names {
        entries.push(format!("{prefix}::{name}"));
    }
}

// Extracts the exported name(s) from a use path fragment.
// Handles `path::X`, `path::{A, B as C}`, stripping `as` aliases to the alias.
fn extract_use_names(inner: &str) -> Vec<String> {
    let last = if let Some(pos) = inner.rfind("::") {
        inner[pos + 2..].trim()
    } else {
        inner.trim()
    };
    if last.starts_with('{') {
        let body = last.trim_matches(|c| c == '{' || c == '}');
        body.split(',')
            .filter_map(|part| {
                let tok = part.trim();
                if tok.is_empty() {
                    return None;
                }
                Some(tok.split_whitespace().last().unwrap_or(tok).to_string())
            })
            .collect()
    } else {
        let name = last.split_whitespace().last().unwrap_or(last);
        vec![name.to_string()]
    }
}

// Collects a `pub fn name(` wrapper function defined directly in a mod block.
fn collect_pub_fn_name(trimmed: &str, mod_stack: &[String], entries: &mut Vec<String>) {
    if let Some(rest) = trimmed.strip_prefix("pub fn ") {
        if let Some(name) = rest.split('<').next().and_then(|s| s.split('(').next()) {
            let prefix = mod_stack.join("::");
            entries.push(format!("{prefix}::{}", name.trim()));
        }
    }
}

// Asserts that actual snapshot equals expected, printing a diff on mismatch.
fn assert_allow_list_matches(actual: &[String], expected: &[&str], label: &str) {
    let missing: Vec<_> = expected
        .iter()
        .filter(|e| !actual.iter().any(|a| a == *e))
        .collect();
    let unexpected: Vec<_> = actual
        .iter()
        .filter(|a| !expected.contains(&a.as_str()))
        .collect();
    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "{label} allow-list snapshot mismatch.\nMissing (removed from source): {missing:?}\nUnexpected (added to source): {unexpected:?}"
    );
}

fn assert_core_alias_does_not_reach_hidden_surface(content: &str, path: &Path) {
    let aliases = core_aliases(content);
    let display_path = path.display();

    for alias in aliases {
        assert!(
            !content.contains(&format!("{alias}::cli_api::test_support")),
            "{display_path} must not use hidden test support through alias {alias}"
        );

        for root in [
            "app", "config", "crypto", "feature", "format", "io", "model", "support",
        ] {
            assert!(
                !content.contains(&format!("{alias}::{root}::")),
                "{display_path} must not use internal root {root} through alias {alias}"
            );
        }
    }
}

fn core_aliases(content: &str) -> Vec<&str> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let alias = trimmed
                .strip_prefix("use kapsaro_core as ")
                .or_else(|| trimmed.strip_prefix("extern crate kapsaro_core as "))?;
            alias.trim_end_matches(';').split_whitespace().next()
        })
        .collect()
}
